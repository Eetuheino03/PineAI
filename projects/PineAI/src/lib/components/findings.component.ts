import { Component } from '@angular/core';
import { PineAIService } from '../services/PineAI.service';
import { Finding } from '../models';

@Component({
    selector: 'lib-pineai-findings',
    templateUrl: './findings.component.html',
    styleUrls: ['./shared.css']
})
export class FindingsComponent {
    statusFilter = 'active';
    severityFilter = 'all';
    busyFindingId = '';
    errorMessage = '';
    notes: {[findingId: string]: string} = {};

    constructor(public pineai: PineAIService) {}

    get visibleFindings(): Finding[] {
        return this.pineai.findings.filter((finding) => {
            const statusMatch = this.statusFilter === 'all' ||
                (this.statusFilter === 'active' &&
                    (finding.status === 'open' || finding.status === 'acknowledged')) ||
                finding.status === this.statusFilter;
            const severityMatch = this.severityFilter === 'all' ||
                finding.severity === this.severityFilter;
            return statusMatch && severityMatch;
        });
    }

    async refresh(): Promise<void> {
        this.errorMessage = '';
        try {
            await this.pineai.refreshFindings();
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        }
    }

    async setStatus(
        finding: Finding,
        status: 'open' | 'acknowledged' | 'false_positive'
    ): Promise<void> {
        if (!this.pineai.assessmentMutable() ||
            (finding.status === 'resolved' && status === 'open')) {
            return;
        }
        const label = status.replace('_', ' ');
        if (!window.confirm(
            `Set finding "${finding.finding_id}" to ${label}?`
        )) {
            return;
        }
        this.busyFindingId = finding.finding_id;
        this.errorMessage = '';
        try {
            await this.pineai.updateFinding(
                finding.finding_id,
                status,
                this.notes[finding.finding_id] || ''
            );
            this.notes[finding.finding_id] = '';
        } catch (error) {
            const failure = this.pineai.error(error);
            this.errorMessage = failure.code === 'revision_conflict'
                ? 'revision_conflict: Latest findings were loaded. Review before retrying.'
                : `${failure.code}: ${failure.message}`;
        } finally {
            this.busyFindingId = '';
        }
    }

    certainty(finding: Finding): string {
        const value: any = finding || {};
        return value.certainty ||
            value.details && value.details.certainty ||
            'legacy read-only history';
    }
}
