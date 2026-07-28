import { Component } from '@angular/core';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-assets-changes',
    templateUrl: './assets-changes.component.html',
    styleUrls: ['./shared.css']
})
export class AssetsChangesComponent {
    busy = false;
    errorMessage = '';
    successMessage = '';

    constructor(public pineai: PineAIService) {}

    get snapshot(): any {
        return this.pineai.resolvedScan
            ? this.pineai.resolvedScan.snapshot || this.pineai.resolvedScan
            : null;
    }

    get accessPoints(): any[] {
        const value = this.snapshot;
        if (!value) {
            return [];
        }
        return value.access_points || value.aps || value.ap_assets || [];
    }

    get networks(): any[] {
        const value = this.snapshot;
        if (!value) {
            return [];
        }
        return value.networks || value.ssids || value.network_assets || [];
    }

    get comparison(): any {
        if (this.pineai.analysis && this.pineai.analysis.comparison) {
            return this.pineai.analysis.comparison;
        }
        return this.pineai.comparison;
    }

    get diff(): any {
        return this.comparison
            ? this.comparison.diff || this.comparison.comparison || {}
            : {};
    }

    get candidateFindings(): any[] {
        const value = this.comparison;
        return value && Array.isArray(value.candidate_findings)
            ? value.candidate_findings : [];
    }

    id(value: any): string {
        return value
            ? value.ap_id || value.network_id || value.asset_id || value.target_id || ''
            : '';
    }

    ssid(value: any): string {
        if (!value) {
            return 'Unknown';
        }
        if (value.hidden || value.ssid === null || value.ssid === '') {
            return 'Hidden network';
        }
        return value.ssid || value.name || 'Unknown';
    }

    groups(): Array<{name: string, items: any[]}> {
        const groups: Array<{name: string, items: any[]}> = [];
        const walk = (prefix: string, value: any): void => {
            if (Array.isArray(value) && value.length) {
                groups.push({name: prefix, items: value});
                return;
            }
            if (value && typeof value === 'object') {
                Object.keys(value).sort().forEach((key) => {
                    walk(prefix ? `${prefix} · ${key}` : key, value[key]);
                });
            }
        };
        walk('', this.diff);
        return groups;
    }

    async resolve(): Promise<void> {
        await this.run(() => this.pineai.resolveSelectedScan(), 'Assets resolved.');
    }

    async compare(): Promise<void> {
        await this.run(
            () => this.pineai.compareSelectedScan(),
            'Read-only comparison complete. Finding lifecycle was not changed.'
        );
    }

    async analyze(): Promise<void> {
        await this.run(
            () => this.pineai.analyzeSelectedScan(),
            'Comparison saved and finding lifecycle updated.'
        );
    }

    private async run(operation: () => Promise<any>, message: string): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            await operation();
            this.successMessage = message;
        } catch (error) {
            const failure = this.pineai.error(error);
            this.errorMessage = failure.code === 'revision_conflict'
                ? 'revision_conflict: Assessment state changed and was refreshed. Review before retrying.'
                : `${failure.code}: ${failure.message}`;
        } finally {
            this.busy = false;
        }
    }
}
