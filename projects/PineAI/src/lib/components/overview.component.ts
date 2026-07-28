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
        if (!this.pineai.activeAssessment) {
            return 'Create or select an assessment for this wireless environment.';
        }
        if (!this.pineai.selectedScanData) {
            return 'Load a saved Recon scan from the Pineapple.';
        }
        if (!this.pineai.resolvedScan) {
            return 'Resolve the selected scan into deterministic assets.';
        }
        if (!this.pineai.activeBaselineId()) {
            return 'Create and explicitly activate the first baseline version.';
        }
        if (!this.pineai.comparison && !this.pineai.analysis) {
            return 'Preview the scan against the active baseline.';
        }
        if (!this.pineai.analysis) {
            return 'Save the comparison to update the finding lifecycle.';
        }
        return 'Review findings and export a deterministic report.';
    }

    get openFindings(): number {
        const counts = this.pineai.findingCounts();
        return (counts.open || 0) + (counts.acknowledged || 0);
    }

    get partialServices(): string[] {
        return Object.keys(this.pineai.panelErrors);
    }

    async refresh(): Promise<void> {
        this.refreshing = true;
        this.errorMessage = '';
        try {
            await this.pineai.initialize();
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.refreshing = false;
        }
    }
}
