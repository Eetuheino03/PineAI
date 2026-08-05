import {RepeatableAuditComponent} from './repeatable-audit.component';
import {
    RepeatableAuditWorkflowFacade
} from '../services/repeatable-audit-workflow.facade';

describe('RepeatableAuditComponent', () => {
    let pineai: any;
    let audit: any;
    let flow: RepeatableAuditWorkflowFacade;
    let component: RepeatableAuditComponent;

    beforeEach(() => {
        pineai = {
            activeAssessment: {
                assessment_id: 'assessment_1',
                name: 'Office',
                revision: 4
            },
            assuranceProfile: {
                assurance_profile_version_id: 'assurance_v0001'
            },
            measurementProfiles: [{
                measurement_profile_id: 'mprofile_1',
                version_id: 'mprofile_r0001',
                revision: 1,
                name: 'Office dual-band',
                status: 'active',
                context: {}
            }],
            baselines: [{baseline_version_id: 'baseline_v0001'}],
            scans: [],
            assessmentMutable: () => true,
            assuranceProfileId: (value: any) =>
                value.assurance_profile_version_id,
            measurementProfileId: (value: any) =>
                value.measurement_profile_id,
            baselineId: (value: any) => value.baseline_version_id,
            selectAssessment: jasmine.createSpy('selectAssessment')
                .and.returnValue(Promise.resolve()),
            refreshScans: jasmine.createSpy('refreshScans')
                .and.returnValue(Promise.resolve([]))
        };
        audit = {
            selectedRun: null,
            measurements: [],
            workflow: {},
            measurementPoints: [{
                measurement_point_id: 'mp_1',
                assessment_id: 'assessment_1',
                location_label: 'North desk',
                status: 'active',
                revision: 1
            }],
            auditRuns: [],
            busyAction: '',
            createAuditRun: jasmine.createSpy('createAuditRun')
                .and.callFake(() => {
                    audit.selectedRun = {
                        audit_run_id: 'ar_1',
                        assessment_id: 'assessment_1',
                        name: 'Morning audit',
                        status: 'draft',
                        revision: 1,
                        assurance_profile_version_id: 'assurance_v0001'
                    };
                    return Promise.resolve({
                        assessment: {assessment_id: 'assessment_1', revision: 5}
                    });
                }),
            pointForMeasurement: () => null,
            activeMeasurement: () => null,
            normalizeError: (value: any) => value
        };
        flow = new RepeatableAuditWorkflowFacade();
        flow.resetForAssessment('assessment_1');
        component = new RepeatableAuditComponent(pineai, audit, flow);
    });

    it('creates a run only with all immutable provenance pins', async () => {
        const point = audit.measurementPoints[0];
        component.runName = 'Morning audit';
        component.togglePoint(point, true);

        await component.createRun();

        expect(audit.createAuditRun).toHaveBeenCalledWith(
            'assessment_1',
            4,
            {
                name: 'Morning audit',
                description: '',
                assurance_profile_version_id: 'assurance_v0001',
                assignments: [{
                    measurement_point_id: 'mp_1',
                    measurement_profile_id: 'mprofile_1',
                    measurement_profile_version_id: 'mprofile_r0001',
                    baseline_version_id: 'baseline_v0001'
                }]
            }
        );
        expect(pineai.activeAssessment.revision).toBe(5);
    });

    it('does not expose radio start or stop actions', () => {
        expect((component as any).startRecon).toBeUndefined();
        expect((component as any).stopRecon).toBeUndefined();
    });

    it('discloses that saved scan settings are operator-declared', () => {
        expect(component.savedScanProvenanceNotice).toContain(
            'operator-declared collection contract'
        );
        expect(component.savedScanProvenanceNotice).toContain(
            'does not independently prove'
        );
    });

    it('shows the backend-authoritative fact digest without a legacy alias', () => {
        component.reportResult = {
            fact_digest: 'c'.repeat(64),
            content_sha256: 'd'.repeat(64),
            format: 'json',
            content: '{}'
        };

        expect(component.reportFactDigest).toBe('c'.repeat(64));
        expect((component.reportResult as any).report_digest).toBeUndefined();
    });

    it('loads only a saved Recon scan before deterministic resolution', async () => {
        const measurement: any = {
            measurement_id: 'arm_1',
            measurement_point_id: 'mp_1',
            status: 'pending',
            revision: 1
        };
        const run: any = {
            audit_run_id: 'ar_1',
            assessment_id: 'assessment_1',
            name: 'Audit',
            status: 'in_progress',
            revision: 2,
            assurance_profile_version_id: 'assurance_v0001'
        };
        audit.selectedRun = run;
        audit.measurements = [measurement];
        audit.activeMeasurement = () => measurement;
        audit.resolveAuditMeasurement = jasmine.createSpy('resolve')
            .and.returnValue(Promise.resolve({
                assessment: {assessment_id: 'assessment_1', revision: 5}
            }));
        pineai.scans = [{
            scan_id: 17,
            date: '2026-07-31T08:00:00Z',
            scan_time: 180,
            band: 'verified-band'
        }];
        pineai.fetchWorkflowScan = jasmine.createSpy('fetchWorkflowScan')
            .and.returnValue(Promise.resolve({APResults: []}));

        await component.selectSavedScan('17');
        await component.resolveMeasurement();

        expect(pineai.fetchWorkflowScan).toHaveBeenCalledWith(pineai.scans[0]);
        expect(audit.resolveAuditMeasurement).toHaveBeenCalledWith(
            'assessment_1',
            4,
            measurement,
            {APResults: []},
            {
                scan_id: 17,
                date: '2026-07-31T08:00:00Z',
                scan_time: 180
            }
        );
    });
});
