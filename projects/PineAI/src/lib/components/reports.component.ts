import { Component } from '@angular/core';
import { PineAIService } from '../services/PineAI.service';
import {ReportScope} from '../models';

@Component({
    selector: 'lib-pineai-reports',
    templateUrl: './reports.component.html',
    styleUrls: ['./shared.css']
})
export class ReportsComponent {
    format: 'json' | 'html' = 'html';
    includeAi = false;
    language: 'en' | 'fi' = 'en';
    selectedFindingIds: string[] = [];
    busy = false;
    errorMessage = '';
    successMessage = '';
    previewVisible = false;
    reportScopeType:
        'comparison' | 'assessment_current' | 'assessment_history' =
        'comparison';
    selectedComparisonId = '';
    privacyProfile: 'local_full' | 'share_safe' = 'local_full';

    constructor(public pineai: PineAIService) {
        this.language = pineai.settings ? pineai.settings.language : 'en';
        try {
            this.selectedComparisonId = pineai.hasComparison()
                ? pineai.comparisonId() : '';
        } catch (_error) {
            this.selectedComparisonId = '';
        }
    }

    selected(findingId: string): boolean {
        return this.selectedFindingIds.indexOf(findingId) !== -1;
    }

    toggle(findingId: string, checked: boolean): void {
        this.selectedFindingIds = this.selectedFindingIds.filter(
            (value) => value !== findingId
        );
        if (checked) {
            this.selectedFindingIds.push(findingId);
        }
    }

    selectActive(): void {
        this.selectedFindingIds = this.pineai.findings
            .filter((finding) =>
                finding.status === 'open' || finding.status === 'acknowledged')
            .map((finding) => finding.finding_id);
    }

    async previewAi(): Promise<void> {
        await this.run(async () => {
            await this.pineai.prepareAiAnalysis(
                this.selectedFindingIds,
                'finding_explanation',
                this.language
            );
            this.previewVisible = true;
        }, 'Exact pseudonymized AI payload prepared.');
    }

    async generateAi(): Promise<void> {
        await this.run(async () => {
            await this.pineai.generateAiAnalysis(
                this.selectedFindingIds,
                'finding_explanation',
                this.language
            );
            this.includeAi = !!this.pineai.aiAnalysisValue();
        }, 'AI request completed. Deterministic results were not modified.');
    }

    comparisons(): any[] {
        return this.pineai.availableComparisons();
    }

    comparisonId(value: any): string {
        return value
            ? value.comparison_id || value.analysis_id ||
              value.snapshot_id || ''
            : '';
    }

    reportScope(): ReportScope {
        const scope: ReportScope = {
            type: this.reportScopeType,
            finding_mode: this.reportScopeType === 'comparison'
                ? 'comparison'
                : this.reportScopeType === 'assessment_current'
                    ? 'active' : 'all',
            statuses: this.reportScopeType === 'assessment_history'
                ? [] : ['open', 'acknowledged', 'resolved'],
            severities: [],
            rule_ids: [],
            subject_ids: [],
            include_evidence: true,
            include_inventory_policy: true,
            include_ai: this.includeAi
        };
        if (this.reportScopeType === 'comparison') {
            scope.comparison_id = this.selectedComparisonId ||
                (this.pineai.hasComparison()
                    ? this.pineai.comparisonId() : '');
        }
        return scope;
    }

    resetReportPreview(): void {
        this.pineai.reportScopePreview = null;
        this.pineai.report = null;
        this.pineai.workflow.setReportScopeDigest('');
        this.successMessage = '';
    }

    privacyChanged(): void {
        if (this.privacyProfile === 'share_safe') {
            this.includeAi = false;
        }
        this.resetReportPreview();
    }

    async prepareReport(): Promise<void> {
        await this.run(async () => {
            await this.pineai.prepareReportScope(
                this.reportScope(),
                this.privacyProfile
            );
        }, 'Authoritative report scope and privacy manifest prepared.');
    }

    async generateReport(): Promise<void> {
        await this.run(async () => {
            await this.pineai.generateReport(
                this.format,
                this.includeAi,
                this.reportScope(),
                this.privacyProfile
            );
        }, `${this.format.toUpperCase()} report generated.`);
    }

    download(): void {
        this.pineai.downloadReport(this.pineai.report);
    }

    aiText(): string {
        const value = this.pineai.aiAnalysis;
        if (!value) {
            return '';
        }
        const analysis = value.analysis || value;
        if (typeof analysis === 'string') {
            return analysis;
        }
        return analysis.report_text || analysis.summary || analysis.explanation ||
            JSON.stringify(analysis, null, 2);
    }

    reportPreview(): string {
        const value = this.pineai.report;
        if (!value) {
            return '';
        }
        const content = value.content !== undefined ? value.content : value.report;
        return typeof content === 'string'
            ? content.slice(0, 12000)
            : JSON.stringify(content === undefined ? value : content, null, 2).slice(0, 12000);
    }

    private async run(operation: () => Promise<void>, message: string): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            await operation();
            this.successMessage = message;
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.busy = false;
        }
    }
}
