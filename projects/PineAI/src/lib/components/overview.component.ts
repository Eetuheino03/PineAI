import { Component } from '@angular/core';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-overview',
    templateUrl: './overview.component.html',
    styleUrls: ['./shared.css']
})
export class OverviewComponent {
    refreshing = false;
    errorMessage = '';

    constructor(public pineai: PineAIService) {}

    get nextAction(): string {
        if (!this.pineai.settings || !this.pineai.settings.supported_bands.length) {
            return 'Configure at least one device-confirmed Recon band in Settings.';
        }
        if (!this.pineai.selectedScanData) {
            return 'Load an existing Recon scan or start a bounded scan.';
        }
        if (!this.pineai.profileResult) {
            return 'Profile the selected Recon scan.';
        }
        if (!this.pineai.selectedTargetIds.length) {
            return 'Select up to ten authorized targets.';
        }
        if (!this.pineai.activeEngagement) {
            return 'Create or select an engagement with an active authorization window.';
        }
        if (!this.pineai.advisorResult) {
            return 'Generate policy-filtered attack-path advice.';
        }
        if (!this.pineai.selectedPathIds.length) {
            return 'Select Recon-capable advisor paths for Adaptive Recon.';
        }
        return 'Review and recommend an Adaptive Recon plan.';
    }

    async refresh(): Promise<void> {
        this.refreshing = true;
        this.errorMessage = '';
        try {
            await Promise.all([
                this.pineai.refreshHealth(),
                this.pineai.refreshSettings(),
                this.pineai.refreshReconStatus(),
                this.pineai.refreshScans(),
                this.pineai.refreshEngagements()
            ]);
        } catch (error) {
            const failure = this.pineai.error(error);
            this.errorMessage = `${failure.code}: ${failure.message}`;
        } finally {
            this.refreshing = false;
        }
    }
}
