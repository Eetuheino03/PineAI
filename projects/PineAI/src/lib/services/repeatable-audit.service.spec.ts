import {RepeatableAuditService} from './repeatable-audit.service';

class ApiStub {
    moduleRequest = jasmine.createSpy('moduleRequest');
}

describe('RepeatableAuditService', () => {
    let api: ApiStub;
    let service: RepeatableAuditService;

    beforeEach(() => {
        api = new ApiStub();
        service = new RepeatableAuditService(api as any);
    });

    it('loads audit state when optional capability telemetry is unavailable', async () => {
        api.moduleRequest.and.callFake((payload: any) => {
            if (payload.action === 'list_measurement_points') {
                return Promise.resolve({measurement_points: []});
            }
            if (payload.action === 'list_audit_runs') {
                return Promise.resolve({audit_runs: []});
            }
            return Promise.reject({
                code: 'optional_unavailable',
                message: 'Optional endpoint unavailable'
            });
        });

        await service.initializeAssessment('assessment_1');

        expect(service.measurementPoints).toEqual([]);
        expect(service.auditRuns).toEqual([]);
        expect(service.telemetry.status).toBe('degraded');
    });

    it('creates location-only measurement points with optimistic revisions', async () => {
        api.moduleRequest.and.callFake((payload: any) => {
            if (payload.action === 'create_measurement_point') {
                return Promise.resolve({
                    assessment: {assessment_id: 'assessment_1', revision: 4},
                    measurement_point: {
                        measurement_point_id: 'mp_1',
                        assessment_id: 'assessment_1',
                        location_label: 'North desk',
                        status: 'active',
                        revision: 1
                    }
                });
            }
            if (payload.action === 'list_measurement_points') {
                return Promise.resolve({measurement_points: []});
            }
            return Promise.reject(new Error(`Unexpected ${payload.action}`));
        });

        await service.createMeasurementPoint('assessment_1', 3, {
            location_label: 'Floor 2',
            operator_instructions: 'Stand beside the marked desk'
        });

        expect(api.moduleRequest).toHaveBeenCalledWith({
            module: 'PineAI',
            action: 'create_measurement_point',
            assessment_id: 'assessment_1',
            expected_assessment_revision: 3,
            measurement_point: {
                location_label: 'Floor 2',
                operator_instructions: 'Stand beside the marked desk'
            }
        });
    });

    it('updates point context through the changes object only', async () => {
        const point: any = {
            measurement_point_id: 'mp_1',
            assessment_id: 'assessment_1',
            location_label: 'Old label',
            status: 'active',
            revision: 2
        };
        api.moduleRequest.and.callFake((payload: any) => {
            if (payload.action === 'update_measurement_point') {
                return Promise.resolve({measurement_point: Object.assign(
                    {}, point, {location_label: 'New label', revision: 3}
                )});
            }
            if (payload.action === 'list_measurement_points') {
                return Promise.resolve({measurement_points: []});
            }
            return Promise.reject(new Error(`Unexpected ${payload.action}`));
        });

        await service.updateMeasurementPoint(
            'assessment_1', 7, point, {location_label: 'New label'}
        );

        expect(api.moduleRequest).toHaveBeenCalledWith({
            module: 'PineAI',
            action: 'update_measurement_point',
            assessment_id: 'assessment_1',
            measurement_point_id: 'mp_1',
            expected_assessment_revision: 7,
            expected_measurement_point_revision: 2,
            changes: {location_label: 'New label'}
        });
    });

    it('reads and archives a point with both authoritative revisions', async () => {
        const point: any = {
            measurement_point_id: 'mp_1',
            assessment_id: 'assessment_1',
            location_label: 'North desk',
            status: 'active',
            revision: 3
        };
        api.moduleRequest.and.callFake((payload: any) => {
            if (payload.action === 'get_measurement_point') {
                return Promise.resolve({measurement_point: point});
            }
            if (payload.action === 'archive_measurement_point') {
                return Promise.resolve({measurement_point: Object.assign(
                    {}, point, {status: 'archived', revision: 4}
                )});
            }
            if (payload.action === 'list_measurement_points') {
                return Promise.resolve({measurement_points: []});
            }
            return Promise.reject(new Error(`Unexpected ${payload.action}`));
        });

        expect((await service.getMeasurementPoint(
            'assessment_1', 'mp_1'
        )).location_label).toBe('North desk');
        await service.archiveMeasurementPoint('assessment_1', 9, point);

        expect(api.moduleRequest).toHaveBeenCalledWith({
            module: 'PineAI',
            action: 'archive_measurement_point',
            assessment_id: 'assessment_1',
            measurement_point_id: 'mp_1',
            expected_assessment_revision: 9,
            expected_measurement_point_revision: 3
        });
    });

    it('pins point, profile, baseline and AssuranceProfile when creating a run', async () => {
        const created = {
            audit_run_id: 'ar_1',
            assessment_id: 'assessment_1',
            name: 'Morning audit',
            status: 'draft',
            revision: 1,
            assurance_profile_version_id: 'assurance_v0003'
        };
        api.moduleRequest.and.callFake((payload: any) => {
            if (payload.action === 'create_audit_run') {
                return Promise.resolve({audit_run: created});
            }
            if (payload.action === 'list_audit_runs') {
                return Promise.resolve({
                    audit_runs: [{
                        audit_run: created,
                        ready_to_start: true,
                        workflow: {
                            current_measurement_id: null,
                            next_measurement_id: null,
                            next_action: 'start_run'
                        }
                    }]
                });
            }
            if (payload.action === 'get_audit_run') {
                return Promise.resolve({
                    audit_run: created,
                    measurements: [],
                    workflow: {
                        current_measurement_id: null,
                        next_measurement_id: null,
                        next_action: 'start_run'
                    }
                });
            }
            return Promise.reject(new Error(`Unexpected ${payload.action}`));
        });
        const assignment = {
            measurement_point_id: 'mp_1',
            measurement_profile_id: 'mprofile_1',
            measurement_profile_version_id: 'mprofile_r0002',
            baseline_version_id: 'baseline_v0001'
        };

        await service.createAuditRun('assessment_1', 8, {
            name: 'Morning audit',
            assurance_profile_version_id: 'assurance_v0003',
            assignments: [assignment]
        });

        expect(api.moduleRequest).toHaveBeenCalledWith({
            module: 'PineAI',
            action: 'create_audit_run',
            assessment_id: 'assessment_1',
            expected_assessment_revision: 8,
            audit_run: {
                name: 'Morning audit',
                assurance_profile_version_id: 'assurance_v0003',
                assignments: [assignment]
            }
        });
        expect(service.selectedRun.audit_run_id).toBe('ar_1');
    });

    it('passes only the selected saved scan to deterministic resolution', async () => {
        const measurement: any = {
            measurement_id: 'arm_1',
            measurement_point_id: 'mp_1',
            status: 'pending',
            revision: 2
        };
        service.selectedRun = {
            audit_run_id: 'ar_1',
            assessment_id: 'assessment_1',
            name: 'Audit',
            status: 'in_progress',
            revision: 5,
            assurance_profile_version_id: 'assurance_v0001'
        };
        api.moduleRequest.and.callFake((payload: any) => {
            if (payload.action === 'resolve_audit_measurement') {
                return Promise.resolve({});
            }
            if (payload.action === 'get_audit_run') {
                return Promise.resolve({
                    audit_run: Object.assign({}, service.selectedRun, {revision: 6}),
                    measurements: [Object.assign({}, measurement, {status: 'resolved', revision: 3})],
                    workflow: {
                        current_measurement_id: 'arm_1',
                        next_measurement_id: 'arm_1',
                        next_action: 'save_comparison'
                    }
                });
            }
            if (payload.action === 'list_audit_runs') {
                return Promise.resolve({audit_runs: [service.selectedRun]});
            }
            return Promise.reject(new Error(`Unexpected ${payload.action}`));
        });
        const scan = {APResults: [{BSSID: '00:11:22:33:44:55'}]};
        const metadata = {scan_id: 17, date: '2026-07-31T08:00:00Z'};

        await service.resolveAuditMeasurement(
            'assessment_1', 11, measurement, scan, metadata
        );

        expect(api.moduleRequest).toHaveBeenCalledWith({
            module: 'PineAI',
            action: 'resolve_audit_measurement',
            assessment_id: 'assessment_1',
            audit_run_id: 'ar_1',
            measurement_id: 'arm_1',
            expected_assessment_revision: 11,
            expected_audit_run_revision: 5,
            expected_measurement_revision: 2,
            scan,
            scan_metadata: metadata
        });
        expect(service.measurements[0].status).toBe('resolved');
    });

    it('executes lifecycle actions against freshly loaded backend revisions', async () => {
        let runRevision = 4;
        let measurementRevision = 2;
        let measurementStatus = 'resolved';
        const mutationActions = [
            'start_audit_run',
            'save_audit_measurement_comparison',
            'retry_audit_measurement',
            'complete_audit_run',
            'cancel_audit_run'
        ];
        api.moduleRequest.and.callFake((payload: any) => {
            if (mutationActions.indexOf(payload.action) >= 0) {
                runRevision++;
                measurementRevision++;
                if (payload.action === 'save_audit_measurement_comparison') {
                    measurementStatus = 'completed';
                } else if (payload.action === 'retry_audit_measurement') {
                    measurementStatus = 'resolved';
                }
                return Promise.resolve({});
            }
            if (payload.action === 'get_audit_run') {
                return Promise.resolve({
                    audit_run: {
                        audit_run_id: 'ar_1',
                        assessment_id: 'assessment_1',
                        name: 'Audit',
                        status: 'in_progress',
                        revision: runRevision,
                        assurance_profile_version_id: 'assurance_v0001'
                    },
                    measurements: [{
                        measurement_id: 'arm_1',
                        measurement_point_id: 'mp_1',
                        status: measurementStatus,
                        revision: measurementRevision,
                        failed_stage: measurementStatus === 'failed'
                            ? 'comparison' : undefined
                    }],
                    workflow: {
                        current_measurement_id: 'arm_1',
                        next_measurement_id: 'arm_1',
                        next_action: 'save_comparison'
                    }
                });
            }
            if (payload.action === 'list_audit_runs') {
                return Promise.resolve({audit_runs: []});
            }
            return Promise.reject(new Error(`Unexpected ${payload.action}`));
        });
        service.selectedRun = {
            audit_run_id: 'ar_1',
            assessment_id: 'assessment_1',
            name: 'Audit',
            status: 'draft',
            revision: runRevision,
            assurance_profile_version_id: 'assurance_v0001'
        };
        service.measurements = [{
            measurement_id: 'arm_1',
            measurement_point_id: 'mp_1',
            status: 'resolved',
            revision: measurementRevision
        }];

        await service.startAuditRun('assessment_1', 10);
        await service.saveAuditMeasurementComparison(
            'assessment_1', 11, service.measurements[0]
        );
        measurementStatus = 'failed';
        service.measurements[0].status = 'failed';
        service.measurements[0].failed_stage = 'comparison';
        await service.retryAuditMeasurement(
            'assessment_1', 12, service.measurements[0]
        );
        await service.completeAuditRun('assessment_1', 13);
        await service.cancelAuditRun('assessment_1', 14);

        mutationActions.forEach((action) => {
            expect(api.moduleRequest).toHaveBeenCalledWith(
                jasmine.objectContaining({module: 'PineAI', action})
            );
        });
    });

    it('normalizes nested resource telemetry for a compact UI', async () => {
        api.moduleRequest.and.returnValue(Promise.resolve({
            status: 'ready',
            memory: {
                process_rss_bytes: 1024,
                process_peak_rss_bytes: 2048,
                mem_available_bytes: 4096
            },
            storage: {free_bytes: 8192},
            artifacts: {total_bytes: 512},
            scan_processing: {status: 'busy'}
        }));

        const value = await service.refreshTelemetry('assessment_1');

        expect(value.process_rss_bytes).toBe(1024);
        expect(value.memory_available_bytes).toBe(4096);
        expect(value.disk_free_bytes).toBe(8192);
        expect(value.assessment_bytes).toBe(512);
        expect(value.scan_processing_busy).toBeTrue();
    });

    it('resolves authoritative workflow IDs and never expects embedded objects', () => {
        const first: any = {
            measurement_id: 'arm_1',
            measurement_point_id: 'mp_1',
            status: 'completed',
            revision: 1
        };
        const second: any = {
            measurement_id: 'arm_2',
            measurement_point_id: 'mp_2',
            status: 'pending',
            revision: 1
        };
        service.measurements = [first, second];
        service.workflow = {
            current_measurement_id: null,
            next_measurement_id: 'arm_2',
            next_action: 'resolve_measurement'
        };
        service.measurementPoints = [{
            measurement_point_id: 'mp_2',
            assessment_id: 'assessment_1',
            location_label: 'South desk',
            status: 'active',
            revision: 1
        }];

        expect(service.activeMeasurement().measurement_id).toBe('arm_2');
        expect(service.pointForMeasurement(second).location_label).toBe('South desk');
        service.workflow = {
            current_measurement_id: null,
            next_measurement_id: null,
            next_action: 'generate_report'
        };
        expect(service.activeMeasurement()).toBeNull();
        service.workflow = {};
        expect(service.activeMeasurement().measurement_id).toBe('arm_2');
        service.measurements = [first];
        expect(service.activeMeasurement()).toBeNull();
    });

    it('loads a runtime-shaped run detail and dereferences workflow IDs locally', async () => {
        const completed: any = {
            measurement_id: 'arm_completed',
            measurement_point_id: 'mp_1',
            status: 'completed',
            revision: 3
        };
        const pending: any = {
            measurement_id: 'arm_pending',
            measurement_point_id: 'mp_2',
            status: 'pending',
            revision: 1
        };
        api.moduleRequest.and.returnValue(Promise.resolve({
            schema_version: '1.0',
            audit_run: {
                audit_run_id: 'ar_runtime',
                assessment_id: 'assessment_1',
                name: 'Runtime-shaped audit',
                status: 'in_progress',
                revision: 7,
                assurance_profile_version_id: 'assurance_v0001'
            },
            measurements: [completed, pending],
            ready_to_start: false,
            workflow: {
                current_measurement_id: 'arm_pending',
                next_measurement_id: 'arm_pending',
                next_action: 'resolve_measurement'
            },
            assessment_capacity: {}
        }));

        const detail = await service.selectAuditRun(
            'assessment_1', 'ar_runtime'
        );

        expect(detail.workflow).toEqual({
            current_measurement_id: 'arm_pending',
            next_measurement_id: 'arm_pending',
            next_action: 'resolve_measurement'
        });
        expect(service.activeMeasurement()).toBe(pending);
        expect((service.workflow as any).current_measurement).toBeUndefined();
        expect((service.workflow as any).next_measurement).toBeUndefined();
    });

    it('returns stable frontend error objects and rejects concurrent actions', async () => {
        expect(service.normalizeError({error: {
            code: 'revision_conflict',
            safe_message: 'Refresh'
        }})).toEqual({code: 'revision_conflict', message: 'Refresh'});
        expect(service.normalizeError(new Error('Network'))).toEqual({
            code: 'request_failed',
            message: 'Network'
        });
        service.busyAction = 'existing_action';

        await expectAsync(service.loadCapabilities()).toBeResolved();
        await expectAsync(service.selectAuditRun(
            'assessment_1', 'ar_1'
        )).toBeRejectedWith(jasmine.objectContaining({code: 'frontend_busy'}));
    });

    it('requests a read-only report using the v0.7 privacy contract', async () => {
        service.selectedRun = {
            audit_run_id: 'ar_1',
            assessment_id: 'assessment_1',
            name: 'Audit',
            status: 'completed',
            revision: 8,
            assurance_profile_version_id: 'assurance_v0001'
        };
        const factDigest = 'b'.repeat(64);
        api.moduleRequest.and.returnValue(Promise.resolve({
            schema_version: '1.0',
            report_id: 'audit_report_bbbbbbbbbbbbbbbb',
            audit_run_id: 'ar_1',
            format: 'json',
            privacy_profile: 'share_safe',
            generated_at: '2026-08-01T10:00:00Z',
            fact_digest: factDigest,
            content: '{}',
            content_sha256: 'a'.repeat(64),
            filename: 'pineassure-ar_1.json',
            mime_type: 'application/json'
        }));

        const result = await service.generateAuditRunReport(
            'assessment_1', 'json', 'share_safe'
        );

        expect(api.moduleRequest).toHaveBeenCalledWith({
            module: 'PineAI',
            action: 'generate_audit_run_report',
            assessment_id: 'assessment_1',
            audit_run_id: 'ar_1',
            format: 'json',
            privacy_profile: 'share_safe'
        });
        expect(result.fact_digest).toBe(factDigest);
        expect((result as any).report_digest).toBeUndefined();
    });
});
