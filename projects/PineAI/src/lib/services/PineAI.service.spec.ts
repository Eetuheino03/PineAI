import { PineAIService } from './PineAI.service';

class ApiStub {
    moduleRequest = jasmine.createSpy('moduleRequest');
    nativeGet = jasmine.createSpy('nativeGet');
    nativePost = jasmine.createSpy('nativePost');
}

describe('PineAIService', () => {
    let api: ApiStub;
    let service: PineAIService;

    beforeEach(() => {
        api = new ApiStub();
        service = new PineAIService(api as any);
        service.settings = {
            schema_version: '1.0',
            model: 'gpt-5.6-terra',
            language: 'en',
            share_ssids: false,
            max_ai_targets: 50,
            supported_bands: [
                {value: 'confirmed', covers: ['2.4'], is_default: true}
            ],
            api_key_configured: false,
            api_key_source: 'none'
        };
    });

    it('limits target selection to ten stable identifiers', () => {
        for (let index = 0; index < 12; index++) {
            service.toggleTarget(
                `target_${(`000000000000${index}`).slice(-12)}`,
                true
            );
        }
        expect(service.selectedTargetIds.length).toBe(10);
        service.toggleTarget(service.selectedTargetIds[0], false);
        expect(service.selectedTargetIds.length).toBe(9);
    });

    it('recognizes only paths containing collect_additional_recon', () => {
        expect(service.pathSupportsAdaptive({
            steps: [{action_id: 'collect_additional_recon'}]
        })).toBeTrue();
        expect(service.pathSupportsAdaptive({
            steps: [{action_id: 'authorized_deauthentication'}]
        })).toBeFalse();
    });

    it('starts manual Recon only with an allowlisted band and exact body', async () => {
        api.nativeGet.and.returnValue(Promise.resolve({
            captureRunning: false,
            scanRunning: false,
            continuous: false,
            scanPercent: 0,
            scanID: 0
        }));
        api.nativePost.and.returnValue(Promise.resolve({
            scanRunning: true,
            scanID: 9
        }));
        await service.startManualRecon('confirmed', 180);
        expect(api.nativePost).toHaveBeenCalledWith('/api/recon/start', {
            live: false,
            scan_time: 180,
            band: 'confirmed'
        });
        await expectAsync(
            service.startManualRecon('invented', 180)
        ).toBeRejectedWith(jasmine.objectContaining({code: 'band_not_supported'}));
    });

    it('does not retain more than five raw-free session snapshot references', () => {
        for (let index = 0; index < 7; index++) {
            service.selectedScan = {scan_id: index, date: new Date(index * 1000).toISOString()};
            service.profileResult = {schema_version: '1.0', targets: []};
            service.addCurrentProfileToHistory({scan_time: 180, band: 'confirmed'});
        }
        expect(service.sessionHistory.length).toBe(5);
        expect(service.sessionHistory[0].scan_metadata.scan_id).toBe(2);
    });

    it('submits an API key once and refreshes only safe status', async () => {
        api.moduleRequest.and.callFake((payload: any) => {
            if (payload.action === 'set_openai_api_key') {
                return Promise.resolve({
                    api_key_configured: true,
                    api_key_source: 'file'
                });
            }
            if (payload.action === 'get_settings') {
                return Promise.resolve(Object.assign({}, service.settings, {
                    api_key_configured: true,
                    api_key_source: 'file'
                }));
            }
            if (payload.action === 'health') {
                return Promise.resolve({status: 'ok'});
            }
            return Promise.reject(new Error('unexpected action'));
        });
        await service.setApiKey('secret-value', false, true);
        expect(api.moduleRequest.calls.first().args[0]).toEqual(
            jasmine.objectContaining({
                action: 'set_openai_api_key',
                api_key: 'secret-value',
                transport_secure: false,
                insecure_transport_acknowledged: true
            })
        );
        expect(JSON.stringify(service.settings)).not.toContain('secret-value');
    });

    it('refreshes an engagement after an optimistic revision conflict', async () => {
        service.activeEngagement = {
            engagement_id: 'eng_test',
            revision: 1,
            name: 'Test'
        };
        api.moduleRequest.and.callFake((payload: any) => {
            if (payload.action === 'update_engagement') {
                return Promise.reject({
                    code: 'revision_conflict',
                    message: 'Engagement changed'
                });
            }
            if (payload.action === 'get_engagement') {
                return Promise.resolve({
                    engagement_id: 'eng_test',
                    revision: 2,
                    name: 'Current'
                });
            }
            return Promise.reject(new Error('unexpected action'));
        });
        await expectAsync(
            service.updateEngagement({name: 'Changed'})
        ).toBeRejectedWith(jasmine.objectContaining({code: 'revision_conflict'}));
        expect(service.activeEngagement.revision).toBe(2);
    });

    it('executes only the exact approved Adaptive Recon descriptor', async () => {
        service.activeEngagement = {
            engagement_id: 'eng_test',
            revision: 1,
            name: 'Test'
        };
        service.adaptivePlan = {
            plan_id: 'reconplan_test',
            candidates: []
        };
        service.reconStatus = {
            captureRunning: false,
            scanRunning: false,
            continuous: false,
            scanPercent: 0,
            scanID: 0
        };
        let engagementRevision = 1;
        const descriptor = {
            method: 'POST',
            path: '/api/recon/start',
            body: {live: false, scan_time: 300, band: 'confirmed'}
        };
        api.nativeGet.and.returnValue(Promise.resolve(service.reconStatus));
        api.nativePost.and.returnValue(Promise.resolve({
            scanRunning: true,
            scanID: 12
        }));
        api.moduleRequest.and.callFake((payload: any) => {
            if (payload.action === 'approve_recon_plan') {
                engagementRevision = 2;
                return Promise.resolve({
                    plan_id: 'reconplan_test',
                    status: 'approved',
                    rest_request: descriptor
                });
            }
            if (payload.action === 'record_recon_scan_started') {
                expect(payload.expected_revision).toBe(2);
                engagementRevision = 3;
                return Promise.resolve({
                    plan_id: 'reconplan_test',
                    status: 'started'
                });
            }
            if (payload.action === 'get_engagement') {
                return Promise.resolve({
                    engagement_id: 'eng_test',
                    revision: engagementRevision,
                    name: 'Test'
                });
            }
            return Promise.reject(new Error('unexpected action'));
        });

        const response = await service.approveAndStartAdaptive('candidate_test');
        expect(response.scanID).toBe(12);
        expect(api.nativePost).toHaveBeenCalledWith(
            '/api/recon/start',
            descriptor.body
        );
        expect(service.adaptivePlan.status).toBe('started');
    });
});
