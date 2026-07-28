import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { PineAIService } from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-settings',
    templateUrl: './settings.component.html',
    styleUrls: ['./shared.css']
})
export class SettingsComponent {
    settingsForm: FormGroup;
    keyForm: FormGroup;
    busy = false;
    errorMessage = '';
    successMessage = '';
    secureTransport = window.location.protocol === 'https:';

    constructor(public pineai: PineAIService, formBuilder: FormBuilder) {
        this.settingsForm = formBuilder.group({
            language: [pineai.settings.language || 'en', Validators.required],
            share_ssids: [!!pineai.settings.share_ssids]
        });
        this.keyForm = formBuilder.group({
            api_key: ['', [Validators.required, Validators.maxLength(1024)]],
            insecure_acknowledged: [false]
        });
    }

    async saveSettings(): Promise<void> {
        if (this.settingsForm.invalid) {
            this.settingsForm.markAllAsTouched();
            return;
        }
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            await this.pineai.saveSettings(
                this.settingsForm.value.language,
                this.settingsForm.value.share_ssids
            );
            this.successMessage = 'Settings saved.';
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.busy = false;
        }
    }

    async saveKey(): Promise<void> {
        if (this.keyForm.invalid ||
            (!this.secureTransport && !this.keyForm.value.insecure_acknowledged)) {
            this.keyForm.markAllAsTouched();
            return;
        }
        const apiKey = this.keyForm.value.api_key;
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            await this.pineai.setApiKey(
                apiKey,
                this.secureTransport,
                this.keyForm.value.insecure_acknowledged
            );
            this.successMessage = 'API key stored on the Pineapple.';
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.keyForm.reset({api_key: '', insecure_acknowledged: false});
            this.busy = false;
        }
    }

    async deleteKey(): Promise<void> {
        if (!window.confirm('Delete the API key managed by PineAI?')) {
            return;
        }
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            await this.pineai.deleteApiKey();
            this.successMessage = 'Managed API key removed.';
        } catch (error) {
            this.errorMessage = this.pineai.errorText(error);
        } finally {
            this.busy = false;
        }
    }
}
