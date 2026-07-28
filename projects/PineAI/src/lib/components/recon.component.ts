import { Component } from '@angular/core';
import { PineAIService } from '../services/PineAI.service';
import { ReconScan } from '../models';

@Component({
    selector: 'lib-pineai-recon',
    templateUrl: './recon.component.html',
    styleUrls: ['./shared.css']
})
export class ReconComponent {
    busy = false;
    loadingScanId: number | string = null;
    errorMessage = '';

    constructor(public pineai: PineAIService) {}

    async refresh(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        try {
            await Promise.all([
                this.pineai.refreshReconStatus(),
                this.pineai.refreshScans()
            ]);
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
            this.pineai.setPanelError('recon', error);
        } finally {
            this.busy = false;
        }
    }

    async load(scan: ReconScan): Promise<void> {
        this.loadingScanId = scan.scan_id;
        this.errorMessage = '';
        try {
            await this.pineai.loadScan(scan);
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.loadingScanId = null;
        }
    }

    async resolve(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        try {
            await this.pineai.resolveSelectedScan();
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.busy = false;
        }
    }
}
