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
    declaredChannelsText = '';

    constructor(public pineai: PineAIService) {}

    onDeclaredChannelsChange(val: string): void {
        this.declaredChannelsText = val;
        if (!val || !val.trim()) {
            this.pineai.measurementContext.declared_channels = [];
            return;
        }
        const nums = val
            .split(/[\s,]+/)
            .map((item) => parseInt(item.trim(), 10))
            .filter((item) => !isNaN(item) && item >= 1 && item <= 200);
        this.pineai.measurementContext.declared_channels = nums;
    }

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

