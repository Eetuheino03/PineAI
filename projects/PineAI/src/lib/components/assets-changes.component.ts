import { Component, OnChanges, SimpleChanges } from '@angular/core';
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

    cachedDiffGroups: Array<{name: string, items: any[]}> = [];
    private lastDiffRef: any = null;

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

    get taxonomy(): any {
        return this.pineai.resultTaxonomy(this.comparison);
    }

    get comparability(): any {
        return this.pineai.comparability(this.comparison);
    }

    get comparabilityLabel(): string {
        return this.pineai.comparabilityLabel(this.comparison);
    }

    itemTitle(value: any): string {
        return value
            ? value.title || value.rule_id || value.change_type ||
              value.type || value.subject_id || value.target_id ||
              'Structured result'
            : 'Structured result';
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

    trackByBssid(index: number, item: any): string {
        return item ? (item.bssid || item.ap_id || index) : index;
    }

    groups(): Array<{name: string, items: any[]}> {
        const currentDiff = this.diff;
        if (this.lastDiffRef === currentDiff) {
            return this.cachedDiffGroups;
        }
        this.lastDiffRef = currentDiff;
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
        walk('', currentDiff);
        this.cachedDiffGroups = groups;
        return groups;
    }

    async resolve(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            await this.pineai.resolveSelectedScan();
            this.successMessage = 'Selected scan resolved successfully.';
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.busy = false;
        }
    }

    async compare(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            await this.pineai.compareSelectedScan();
            this.successMessage = 'Comparison preview generated.';
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.busy = false;
        }
    }

    async analyze(): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            await this.pineai.analyzeSelectedScan();
            this.successMessage = 'Analysis saved successfully.';
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.busy = false;
        }
    }
}
