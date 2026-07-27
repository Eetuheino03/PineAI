import { Component, OnDestroy } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { PineAIService } from '../services/PineAI.service';
import { ReconScan } from '../models';

@Component({
    selector: 'lib-pineai-recon',
    templateUrl: './recon.component.html',
    styleUrls: ['./shared.css']
})
export class ReconComponent implements OnDestroy {
    form: FormGroup;
    loadingScanId: number = null;
    busy = false;
    errorMessage = '';
    private polling: any = null;

    constructor(public pineai: PineAIService, formBuilder: FormBuilder) {
        this.form = formBuilder.group({
            band: ['', Validators.required],
            duration: [180, Validators.required],
            confirmed: [false, Validators.requiredTrue]
        });
        this.beginPolling();
    }

    ngOnDestroy(): void {
        if (this.polling) {
            clearInterval(this.polling);
        }
    }

    async refresh(): Promise<void> {
        this.errorMessage = '';
        try {
            await Promise.all([
                this.pineai.refreshReconStatus(),
                this.pineai.refreshScans()
            ]);
        } catch (error) {
            this.showError(error);
        }
    }

    async load(scan: ReconScan): Promise<void> {
        this.loadingScanId = scan.scan_id;
        this.errorMessage = '';
        try {
            await this.pineai.loadScan(scan);
        } catch (error) {
            this.showError(error);
        } finally {
            this.loadingScanId = null;
        }
    }

    async start(): Promise<void> {
        if (this.form.invalid) {
            this.form.markAllAsTouched();
            return;
        }
        this.busy = true;
        this.errorMessage = '';
        try {
            await this.pineai.startManualRecon(
                this.form.value.band,
                Number(this.form.value.duration)
            );
            this.form.patchValue({confirmed: false});
            await this.pineai.refreshReconStatus();
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    async stop(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        try {
            await this.pineai.stopRecon();
            await this.pineai.refreshReconStatus();
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    private beginPolling(): void {
        this.polling = setInterval(async () => {
            if (!this.pineai.initialized) {
                return;
            }
            try {
                const wasRunning = Boolean(
                    this.pineai.reconStatus && this.pineai.reconStatus.scanRunning
                );
                await this.pineai.refreshReconStatus();
                if (wasRunning && !this.pineai.reconStatus.scanRunning) {
                    await this.pineai.refreshScans();
                    this.pineai.log('success', 'Recon finished', 'Saved scans refreshed.');
                }
            } catch (_error) {
                // Poll failures remain non-fatal; explicit refresh exposes the error.
            }
        }, 3000);
    }

    private showError(error: any): void {
        const failure = this.pineai.error(error);
        this.errorMessage = `${failure.code}: ${failure.message}`;
    }
}
