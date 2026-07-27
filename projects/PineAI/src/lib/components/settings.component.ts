import { Component, OnInit } from '@angular/core';
import { FormArray, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-settings',
    templateUrl: './settings.component.html',
    styleUrls: ['./shared.css']
})
export class SettingsComponent implements OnInit {
    settingsForm: FormGroup;
    keyForm: FormGroup;
    busy = false;
    errorMessage = '';
    successMessage = '';
    secureTransport = window.location.protocol === 'https:';

    constructor(public pineai: PineAIService, private formBuilder: FormBuilder) {
        this.settingsForm = formBuilder.group({
            language: ['en', Validators.required],
            share_ssids: [false],
            supported_bands: formBuilder.array([])
        });
        this.keyForm = formBuilder.group({
            api_key: ['', [Validators.required, Validators.maxLength(1024)]],
            insecure_acknowledged: [false]
        });
    }

    ngOnInit(): void {
        this.loadForm();
    }

    get bands(): FormArray {
        return this.settingsForm.get('supported_bands') as FormArray;
    }

    addBand(value: any = null): void {
        this.bands.push(this.formBuilder.group({
            value: [value ? value.value : '', [
                Validators.required,
                Validators.maxLength(32),
                Validators.pattern(/^[\x20-\x7e]+$/)
            ]],
            cover24: [value ? value.covers.indexOf('2.4') !== -1 : true],
            cover5: [value ? value.covers.indexOf('5') !== -1 : false],
            is_default: [value ? value.is_default : false]
        }));
    }

    removeBand(index: number): void {
        this.bands.removeAt(index);
    }

    async saveSettings(): Promise<void> {
        this.clearMessages();
        if (this.settingsForm.invalid || this.bands.length > 8) {
            this.settingsForm.markAllAsTouched();
            return;
        }
        const supported = this.bands.controls.map((control) => {
            const value = control.value;
            const covers = [];
            if (value.cover24) {
                covers.push('2.4');
            }
            if (value.cover5) {
                covers.push('5');
            }
            return {
                value: value.value,
                covers,
                is_default: Boolean(value.is_default)
            };
        });
        if (supported.some((band) => !band.covers.length)) {
            this.errorMessage = 'Each band must cover 2.4 GHz, 5 GHz, or both.';
            return;
        }
        if (supported.filter((band) => band.is_default).length > 1) {
            this.errorMessage = 'Only one band can be the default.';
            return;
        }
        this.busy = true;
        try {
            await this.pineai.saveSettings(
                this.settingsForm.value.language,
                this.settingsForm.value.share_ssids,
                supported as any
            );
            this.successMessage = 'Settings saved.';
            this.loadForm();
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    async saveKey(): Promise<void> {
        this.clearMessages();
        const acknowledged = Boolean(this.keyForm.value.insecure_acknowledged);
        if (
            this.keyForm.get('api_key').invalid ||
            (!this.secureTransport && !acknowledged)
        ) {
            this.keyForm.markAllAsTouched();
            return;
        }
        this.busy = true;
        const key = this.keyForm.value.api_key;
        try {
            await this.pineai.setApiKey(key, this.secureTransport, acknowledged);
            this.successMessage = 'OpenAI API key stored on the Pineapple.';
        } catch (error) {
            this.showError(error);
        } finally {
            this.keyForm.reset({api_key: '', insecure_acknowledged: false});
            this.busy = false;
        }
    }

    async deleteKey(): Promise<void> {
        if (!window.confirm('Delete the OpenAI API key managed by PineAI?')) {
            return;
        }
        this.clearMessages();
        this.busy = true;
        try {
            await this.pineai.deleteApiKey();
            this.successMessage = this.pineai.settings.api_key_configured
                ? 'Managed key removed. An environment-provided key remains active.'
                : 'Managed OpenAI API key removed.';
        } catch (error) {
            this.showError(error);
        } finally {
            this.busy = false;
        }
    }

    private loadForm(): void {
        if (!this.pineai.settings) {
            return;
        }
        this.settingsForm.patchValue({
            language: this.pineai.settings.language,
            share_ssids: this.pineai.settings.share_ssids
        });
        while (this.bands.length) {
            this.bands.removeAt(0);
        }
        for (const band of this.pineai.settings.supported_bands || []) {
            this.addBand(band);
        }
    }

    private clearMessages(): void {
        this.errorMessage = '';
        this.successMessage = '';
    }

    private showError(error: any): void {
        const failure = this.pineai.error(error);
        this.errorMessage = `${failure.code}: ${failure.message}`;
    }
}
