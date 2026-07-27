import { Component, OnDestroy } from '@angular/core';
import { PineAIService } from '../services/PineAI.service';
import { ReconScan } from '../models';

@Component({
    selector: 'lib-pineai-adaptive-recon',
    templateUrl: './adaptive-recon.component.html',
    styleUrls: ['./shared.css']
})
export class AdaptiveReconComponent implements OnDestroy {
    busy = false;
    errorMessage = '';
    preview: any = null;
    selectedCandidateId = '';
    approvalConfirmed = false;
    runningScanId: number = null;
    private polling: any = null;
    private finalizing = false;

    constructor(public pineai: PineAIService) {}

    ngOnDestroy(): void {
        this.stopPolling();
    }

    async showPreview(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        try {
            this.preview = await this.pineai.prepareAdaptive();
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    async recommend(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        this.preview = null;
        try {
            const plan = await this.pineai.recommendAdaptive();
            this.selectedCandidateId = plan.selected_candidate_id;
            this.approvalConfirmed = false;
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    async approveAndStart(): Promise<void> {
        if (!this.selectedCandidateId || !this.approvalConfirmed) {
            return;
        }
        const candidate = (this.pineai.adaptivePlan.candidates || []).find(
            (value) => value.candidate_id === this.selectedCandidateId
        );
        if (!candidate) {
            this.errorMessage = 'unknown_candidate: Select a candidate returned by the backend.';
            return;
        }
        this.busy = true;
        this.errorMessage = '';
        try {
            this.pineai.addCurrentProfileToHistory(candidate.request);
            const response = await this.pineai.approveAndStartAdaptive(
                this.selectedCandidateId
            );
            this.runningScanId = response.scanID;
            this.approvalConfirmed = false;
            this.beginPolling();
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    async stopAndAbort(): Promise<void> {
        if (this.runningScanId === null) {
            return;
        }
        this.busy = true;
        this.errorMessage = '';
        try {
            await this.pineai.stopRecon();
            await this.pineai.finishAdaptive(
                'aborted',
                this.runningScanId,
                null,
                'operator_aborted'
            );
            this.runningScanId = null;
            this.stopPolling();
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    private beginPolling(): void {
        this.stopPolling();
        this.polling = setInterval(async () => {
            if (this.finalizing || this.runningScanId === null) {
                return;
            }
            try {
                const status = await this.pineai.refreshReconStatus();
                if (!status.scanRunning) {
                    await this.finalizeCompleted();
                }
            } catch (error) {
                this.showError(error);
            }
        }, 3000);
    }

    private stopPolling(): void {
        if (this.polling) {
            clearInterval(this.polling);
            this.polling = null;
        }
    }

    private async finalizeCompleted(): Promise<void> {
        this.finalizing = true;
        this.stopPolling();
        const scanId = this.runningScanId;
        try {
            const scan = await this.waitForScan(scanId);
            if (!scan) {
                await this.pineai.finishAdaptive(
                    'failed', scanId, null, 'scan_result_unavailable'
                );
                this.errorMessage =
                    'scan_result_unavailable: Recon stopped but the saved scan was not returned.';
                return;
            }
            await this.pineai.loadScan(scan, true);
            const completedProfile = await this.pineai.profileSelectedScan(true, true);
            await this.pineai.finishAdaptive(
                'completed', scanId, completedProfile, null
            );
            this.pineai.advisorResult = null;
            this.pineai.selectedPathIds = [];
            this.pineai.log(
                'success',
                'New profiling round ready',
                'Run the Advisor again before another Adaptive Recon plan.'
            );
        } catch (error) {
            this.showError(error);
        } finally {
            this.runningScanId = null;
            this.finalizing = false;
        }
    }

    private async waitForScan(scanId: number): Promise<ReconScan> {
        for (let attempt = 0; attempt < 5; attempt++) {
            await this.pineai.refreshScans();
            const match = this.pineai.scans.find((scan) => scan.scan_id === scanId);
            if (match) {
                return match;
            }
            await new Promise((resolve) => setTimeout(resolve, 1000));
        }
        return null;
    }

    private showError(error: any): void {
        const failure = this.pineai.error(error);
        this.errorMessage = `${failure.code}: ${failure.message}`;
    }
}
