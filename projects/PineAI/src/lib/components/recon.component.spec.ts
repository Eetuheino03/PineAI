import { ReconComponent } from './recon.component';
import { PineAIService } from '../services/PineAI.service';
import { MeasurementContext } from '../models';

class ApiStub {
    moduleRequest = jasmine.createSpy('moduleRequest');
    nativeGet = jasmine.createSpy('nativeGet');
}

describe('ReconComponent', () => {
    it('synchronizes declared channel text from the selected scan measurement context', async () => {
        const api = new ApiStub();
        api.nativeGet.and.returnValue(Promise.resolve({APResults: []}));
        const service = new PineAIService(api as any);
        const selectedContext: MeasurementContext = {
            location_id: 'office',
            measurement_point_id: 'entrance',
            scan_profile_id: 'full',
            radio_profile_id: 'mark-vii',
            interface: 'wlan1mon',
            declared_channels: [1, 6, 11, 36]
        };
        service.measurementContextByScan['scan-42'] = selectedContext;
        const component = new ReconComponent(service);

        await component.load({
            scan_id: 'scan-42',
            date: '2026-07-28T00:00:00Z'
        });

        expect(api.nativeGet).toHaveBeenCalledWith('/api/recon/scans/scan-42');
        expect(service.measurementContext).toBe(selectedContext);
        expect(component.declaredChannelsText).toBe('1, 6, 11, 36');
        expect(component.loadingScanId).toBeNull();
    });
});
