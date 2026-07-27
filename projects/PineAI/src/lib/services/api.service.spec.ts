import { TestBed } from '@angular/core/testing';
import {
    HttpClientTestingModule,
    HttpTestingController
} from '@angular/common/http/testing';
import { RouterTestingModule } from '@angular/router/testing';
import { ApiService } from './api.service';

describe('ApiService', () => {
    let service: ApiService;
    let http: HttpTestingController;

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [HttpClientTestingModule, RouterTestingModule]
        });
        service = TestBed.inject(ApiService);
        http = TestBed.inject(HttpTestingController);
        window['_app_base'] = '';
    });

    afterEach(() => {
        http.verify();
    });

    it('unwraps Hak5 module payloads without requiring the global busy element', async () => {
        const promise = service.moduleRequest<any>({
            module: 'PineAI',
            action: 'health'
        });
        const request = http.expectOne('/api/module/request');
        expect(request.request.method).toBe('POST');
        request.flush({payload: {status: 'ok'}});
        await expectAsync(promise).toBeResolvedTo({status: 'ok'});
    });

    it('rejects backend module errors with the safe error object', async () => {
        const promise = service.moduleRequest<any>({
            module: 'PineAI',
            action: 'profile_recon'
        });
        http.expectOne('/api/module/request').flush({
            error: {code: 'invalid_recon', message: 'Invalid Recon data'}
        });
        await expectAsync(promise).toBeRejectedWith(
            jasmine.objectContaining({code: 'invalid_recon'})
        );
    });

    it('preserves native Hak5 paths and request bodies', async () => {
        const body = {live: false, scan_time: 180, band: 'confirmed'};
        const promise = service.nativePost<any>('/api/recon/start', body);
        const request = http.expectOne('/api/recon/start');
        expect(request.request.method).toBe('POST');
        expect(request.request.body).toEqual(body);
        request.flush({scanRunning: true, scanID: 7});
        await expectAsync(promise).toBeResolvedTo({scanRunning: true, scanID: 7});
    });
});
