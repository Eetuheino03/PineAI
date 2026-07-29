import { Component, OnDestroy, OnInit } from '@angular/core';
import { PineAIService } from '../services/PineAI.service';
import { Finding } from '../models';

@Component({
    selector: 'lib-pineai-findings',
    templateUrl: './findings.component.html',
    styleUrls: ['./shared.css']
})
export class FindingsComponent implements OnInit, OnDestroy {
    statusFilter = 'active';
    severityFilter = 'all';
    searchQuery = '';
    busyFindingId = '';
    errorMessage = '';
    notes: {[findingId: string]: string} = {};
    selectedFinding: Finding | null = null;
    filteredFindings: Finding[] = [];
    private searchDebounceTimer: any = null;

    constructor(public pineai: PineAIService) {}

    async ngOnInit(): Promise<void> {
        this.applyFilters();
    }

    ngOnDestroy(): void {
        if (this.searchDebounceTimer) {
            clearTimeout(this.searchDebounceTimer);
            this.searchDebounceTimer = null;
        }
    }

    applyFilters(): void {
        const query = (this.searchQuery || '').trim().toLowerCase();
        this.filteredFindings = (this.pineai.findings || []).filter((finding) => {
            const statusMatch = this.statusFilter === 'all' ||
                (this.statusFilter === 'active' &&
                    (finding.status === 'open' || finding.status === 'acknowledged')) ||
                finding.status === this.statusFilter;
            const severityMatch = this.severityFilter === 'all' ||
                finding.severity === this.severityFilter;
            const textMatch = !query ||
                (finding.title && finding.title.toLowerCase().includes(query)) ||
                (finding.rule_id && finding.rule_id.toLowerCase().includes(query)) ||
                (finding.subject_id && finding.subject_id.toLowerCase().includes(query)) ||
                (finding.finding_id && finding.finding_id.toLowerCase().includes(query)) ||
                (finding.summary && finding.summary.toLowerCase().includes(query));
            return statusMatch && severityMatch && textMatch;
        });

        if (this.selectedFinding) {
            const stillVisible = this.filteredFindings.find(
                (item) => item.finding_id === this.selectedFinding.finding_id
            );
            this.selectedFinding = stillVisible || this.filteredFindings[0] || null;
        } else {
            this.selectedFinding = this.filteredFindings[0] || null;
        }
    }

    onFilterChange(): void {
        this.applyFilters();
    }

    onSearchChange(): void {
        if (this.searchDebounceTimer) {
            clearTimeout(this.searchDebounceTimer);
        }
        this.searchDebounceTimer = setTimeout(() => {
            this.applyFilters();
            this.searchDebounceTimer = null;
        }, 200);
    }

    selectFinding(finding: Finding): void {
        this.selectedFinding = finding;
    }

    trackByFindingId(index: number, finding: Finding): string {
        return finding ? (finding.finding_id || index.toString()) : index.toString();
    }

    async refresh(): Promise<void> {
        this.errorMessage = '';
        try {
            await this.pineai.refreshFindings();
            this.applyFilters();
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
            this.applyFilters();
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
            (value.details && value.details.certainty) ||
            'legacy read-only history';
    }
}
