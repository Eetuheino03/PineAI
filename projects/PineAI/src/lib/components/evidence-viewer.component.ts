import {Component, Input} from '@angular/core';
import {
    EvidenceBundle,
    EvidencePair,
    EvidenceValue,
    Finding
} from '../models';
import {PineAIService} from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-evidence-viewer',
    templateUrl: './evidence-viewer.component.html',
    styleUrls: ['./shared.css']
})
export class EvidenceViewerComponent {
    @Input() finding: Finding;
    @Input() comparisonId = '';

    bundle: EvidenceBundle = null;
    busy = false;
    expanded = false;
    errorMessage = '';

    constructor(public pineai: PineAIService) {}

    async toggle(): Promise<void> {
        this.expanded = !this.expanded;
        if (!this.expanded || this.bundle || !this.finding) {
            return;
        }
        this.busy = true;
        this.errorMessage = '';
        try {
            this.bundle = await this.pineai.loadEvidenceBundle(
                this.itemId(),
                this.comparisonId || undefined
            );
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.busy = false;
        }
    }

    pairs(): EvidencePair[] {
        return this.bundle && Array.isArray(this.bundle.pairs)
            ? this.bundle.pairs : [];
    }

    itemId(): string {
        const finding: any = this.finding || {};
        return finding.source_result_id ||
            finding.change_id ||
            finding.deviation_id ||
            finding.details && finding.details.source_result_id ||
            finding.finding_id || '';
    }

    displayValue(value: EvidenceValue | null): string {
        if (!value) {
            return 'Not observed';
        }
        if (value.value === null || value.value === undefined) {
            return 'No value';
        }
        if (typeof value.value === 'string') {
            return value.value;
        }
        return JSON.stringify(value.value, null, 2);
    }
}
