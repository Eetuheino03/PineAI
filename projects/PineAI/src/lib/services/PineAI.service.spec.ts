import { PineAIService } from './PineAI.service';

class ApiStub {
    moduleRequest = jasmine.createSpy('moduleRequest');
    nativeGet = jasmine.createSpy('nativeGet');
    APIDownload = jasmine.createSpy('APIDownload');
}

describe('PineAIService Baseline & Drift', () => {
    let api: ApiStub;
    let service: PineAIService;

    beforeEach(() => {
        api = new ApiStub();
        service = new PineAIService(api as any);
    });

    it('initializes when optional settings, Recon and assessment calls fail', async () => {
        api.moduleRequest.and.callFake((payload: any) => {
            if (payload.action === 'health') {
                return Promise.resolve({status: 'ok', version: '0.6.1'});
            }
            if (payload.action === 'assurance_capabilities') {
                return Promise.resolve({schema_version: '1.0'});
            }
            return Promise.reject({code: 'offline', message: 'Unavailable'});
        });
        api.nativeGet.and.returnValue(Promise.reject({
            code: 'recon_unavailable',
            message: 'Recon unavailable'
        }));

        await service.initialize();

        expect(service.initialized).toBeTrue();
        expect(service.panelErrors.settings.code).toBe('offline');
        expect(service.panelErrors.recon.code).toBe('recon_unavailable');
        expect(service.panelErrors.assessments.code).toBe('offline');
        expect(service.settings.share_ssids).toBeFalse();
    });

    it('blocks initialization when the core health action fails', async () => {
        api.moduleRequest.and.returnValue(Promise.reject({
            code: 'backend_unavailable',
            message: 'Backend unavailable'
        }));

        await expectAsync(service.initialize()).toBeRejected();
        expect(service.initialized).toBeFalse();
    });

    it('uses only saved Recon GET endpoints and clears downstream state', async () => {
        service.comparison = {comparison_id: 'old'};
        service.analysis = {comparison: {comparison_id: 'old'}};
        service.resolvedScan = {snapshot: {}};
        api.nativeGet.and.returnValue(Promise.resolve({APResults: []}));

        await service.loadScan({scan_id: 17, date: '2026-07-27T10:00:00Z'});

        expect(api.nativeGet).toHaveBeenCalledWith('/api/recon/scans/17');
        expect(service.resolvedScan).toBeNull();
        expect(service.comparison).toBeNull();
        expect(service.analysis).toBeNull();
    });

    it('passes exact scan data to baseline creation and refreshes revision', async () => {
        service.selectedScan = {
            scan_id: 17,
            date: '2026-07-27T10:00:00Z',
            ui_only_field: 'must-not-cross-boundary'
        };
        service.selectedScanData = {APResults: []};
        service.resolvedScan = {schema_version: '1.0', snapshot: {access_points: []}};
        service.activeAssessment = {
            assessment_id: 'assessment_1',
            name: 'Office',
            revision: 3
        };
        api.moduleRequest.and.callFake((payload: any) => {
            if (payload.action === 'create_baseline_version') {
                return Promise.resolve({
                    assessment: Object.assign({}, service.activeAssessment, {revision: 4}),
                    baseline: {baseline_version: 'baseline_1'}
                });
            }
            if (payload.action === 'get_assessment') {
                return Promise.resolve({
                    assessment: Object.assign({}, service.activeAssessment, {revision: 4}),
                    events: []
                });
            }
            if (payload.action === 'list_baseline_versions') {
                return Promise.resolve({
                    active_baseline_version: null,
                    baselines: [{baseline_version: 'baseline_1'}]
                });
            }
            if (payload.action === 'list_findings') {
                return Promise.resolve({findings: []});
            }
            if (payload.action === 'list_assessments') {
                return Promise.resolve({assessments: []});
            }
            return Promise.reject(new Error(`Unexpected ${payload.action}`));
        });

        await service.createBaselineVersion('Initial');

        expect(api.moduleRequest).toHaveBeenCalledWith(jasmine.objectContaining({
            action: 'create_baseline_version',
            assessment_id: 'assessment_1',
            expected_revision: 3,
            scan: {APResults: []},
            scan_metadata: {
                scan_id: 17,
                date: '2026-07-27T10:00:00Z'
            },
            label: 'Initial'
        }));
        expect(service.activeAssessment.revision).toBe(4);
    });

    it('uses the latest persisted comparison after a page reload', () => {
        service.activeAssessment = {
            assessment_id: 'assessment_1',
            name: 'Office',
            revision: 7,
            comparisons: [
                {comparison_id: 'comparison_0123456789abcdef'}
            ]
        };
        service.analysis = null;
        service.comparison = null;

        expect(service.hasComparison()).toBeTrue();
        expect(service.comparisonId()).toBe('comparison_0123456789abcdef');
    });

    it('refreshes an assessment after an optimistic revision conflict', async () => {
        service.activeAssessment = {
            assessment_id: 'assessment_1',
            revision: 1,
            name: 'Old'
        };
        api.moduleRequest.and.callFake((payload: any) => {
            if (payload.action === 'update_assessment') {
                return Promise.reject({
                    code: 'revision_conflict',
                    message: 'Assessment changed'
                });
            }
            if (payload.action === 'get_assessment') {
                return Promise.resolve({
                    assessment: {
                        assessment_id: 'assessment_1',
                        revision: 2,
                        name: 'Current'
                    },
                    events: []
                });
            }
            if (payload.action === 'list_baseline_versions') {
                return Promise.resolve({baselines: []});
            }
            if (payload.action === 'list_findings') {
                return Promise.resolve({findings: []});
            }
            return Promise.reject(new Error(`Unexpected ${payload.action}`));
        });

        await expectAsync(
            service.updateAssessment({name: 'Changed'})
        ).toBeRejectedWith(jasmine.objectContaining({code: 'revision_conflict'}));
        expect(service.activeAssessment.revision).toBe(2);
        expect(service.activeAssessment.name).toBe('Current');
    });

    it('does not put authoritative values under AI control', async () => {
        service.activeAssessment = {
            assessment_id: 'assessment_1',
            revision: 2,
            name: 'Office'
        };
        service.settings = Object.assign({}, service.settings, {
            language: 'fi',
            share_ssids: false
        });
        service.comparison = {comparison_id: 'comparison_1'};
        api.moduleRequest.and.returnValue(Promise.resolve({
            payload: {targets: ['target_1']}
        }));

        await service.prepareAiAnalysis(
            ['finding_1'], 'finding_explanation', 'fi'
        );

        const request = api.moduleRequest.calls.mostRecent().args[0];
        expect(request).toEqual(jasmine.objectContaining({
            action: 'prepare_ai_analysis',
            assessment_id: 'assessment_1',
            comparison_id: 'comparison_1',
            finding_ids: ['finding_1'],
            options: {language: 'fi', share_ssids: false}
        }));
        expect(JSON.stringify(request)).not.toContain('severity');
        expect(JSON.stringify(request)).not.toContain('confidence');
    });

    it('downloads a backend-generated report path without exposing its content', () => {
        service.downloadReport({
            filename: 'PineAI-report.html',
            path: '/root/.PineAI/reports/report.html'
        });
        expect(api.APIDownload).toHaveBeenCalledWith(
            '/root/.PineAI/reports/report.html',
            'PineAI-report.html'
        );
    });
});
