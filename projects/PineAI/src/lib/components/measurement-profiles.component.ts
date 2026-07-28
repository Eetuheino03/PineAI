import {Component} from '@angular/core';
import {FormBuilder, FormGroup, Validators} from '@angular/forms';
import {MeasurementContext, MeasurementProfile} from '../models';
import {PineAIService} from '../services/PineAI.service';

@Component({
    selector: 'lib-pineai-measurement-profiles',
    templateUrl: './measurement-profiles.component.html',
    styleUrls: ['./shared.css']
})
export class MeasurementProfilesComponent {
    form: FormGroup;
    selected: MeasurementProfile = null;
    channelsText = '';
    busy = false;
    includeArchived = false;
    errorMessage = '';
    successMessage = '';

    constructor(
        public pineai: PineAIService,
        formBuilder: FormBuilder
    ) {
        this.form = formBuilder.group({
            name: ['', [Validators.required, Validators.maxLength(100)]],
            description: ['', Validators.maxLength(500)],
            location_id: ['', [Validators.required, Validators.maxLength(100)]],
            measurement_point_id: [
                '',
                [Validators.required, Validators.maxLength(100)]
            ],
            scan_profile_id: [
                '',
                [Validators.required, Validators.maxLength(100)]
            ],
            radio_profile_id: [
                '',
                [Validators.required, Validators.maxLength(100)]
            ],
            interface: [
                '',
                [Validators.required, Validators.maxLength(64)]
            ],
            band_2_4: [true],
            band_5: [false],
            scan_time: [
                180,
                [Validators.required, Validators.min(30), Validators.max(3600)]
            ],
            five_ghz_operator_confirmed: [false],
            is_default: [false]
        });
    }

    newProfile(): void {
        this.selected = null;
        this.channelsText = '';
        this.errorMessage = '';
        this.successMessage = '';
        this.form.reset({
            name: '',
            description: '',
            location_id: '',
            measurement_point_id: '',
            scan_profile_id: '',
            radio_profile_id: '',
            interface: '',
            band_2_4: true,
            band_5: false,
            scan_time: 180,
            five_ghz_operator_confirmed: false,
            is_default: false
        });
    }

    edit(profile: MeasurementProfile): void {
        const context = profile.context || {};
        this.selected = profile;
        this.channelsText = (context.declared_channels || []).join(', ');
        this.form.setValue({
            name: profile.name || '',
            description: profile.description || '',
            location_id: context.location_id || '',
            measurement_point_id: context.measurement_point_id || '',
            scan_profile_id: context.scan_profile_id || '',
            radio_profile_id: context.radio_profile_id || '',
            interface: context.interface || '',
            band_2_4: (context.declared_bands || []).indexOf('2.4') !== -1,
            band_5: (context.declared_bands || []).indexOf('5') !== -1,
            scan_time: context.scan_time || 180,
            five_ghz_operator_confirmed:
                !!context.five_ghz_operator_confirmed,
            is_default: !!profile.is_default
        });
        this.errorMessage = '';
        this.successMessage = '';
    }

    apply(profile: MeasurementProfile): void {
        this.pineai.applyMeasurementProfile(profile);
        this.successMessage =
            `Profile "${profile.name}" copied into the current session.`;
    }

    async refresh(): Promise<void> {
        await this.run(async () => {
            await this.pineai.refreshMeasurementProfiles(this.includeArchived);
        }, 'Profiles refreshed.');
    }

    async save(): Promise<void> {
        const value = this.form.value;
        if (this.form.invalid || !this.channels().length ||
            (!value.band_2_4 && !value.band_5) ||
            (value.band_5 && !value.five_ghz_operator_confirmed)) {
            this.form.markAllAsTouched();
            if (!this.channels().length) {
                this.errorMessage =
                    'validation_error: Declare at least one valid channel (1–196).';
            } else if (!value.band_2_4 && !value.band_5) {
                this.errorMessage =
                    'validation_error: Declare at least one covered band.';
            } else if (value.band_5 &&
                !value.five_ghz_operator_confirmed) {
                this.errorMessage =
                    'five_ghz_confirmation_required: Confirm the actual 5 GHz radio capability.';
            }
            return;
        }
        const context: MeasurementContext = {
            location_id: value.location_id.trim(),
            measurement_point_id: value.measurement_point_id.trim(),
            scan_profile_id: value.scan_profile_id.trim(),
            radio_profile_id: value.radio_profile_id.trim(),
            interface: value.interface.trim(),
            declared_channels: this.channels(),
            declared_bands: [
                value.band_2_4 ? '2.4' : null,
                value.band_5 ? '5' : null
            ].filter((item) => !!item) as string[],
            scan_time: Number(value.scan_time),
            five_ghz_operator_confirmed:
                !!value.five_ghz_operator_confirmed
        };
        await this.run(async () => {
            if (this.selected) {
                const updated = await this.pineai.updateMeasurementProfile(
                    this.selected,
                    {
                        name: value.name.trim(),
                        description: value.description.trim(),
                        is_default: !!value.is_default,
                        context
                    }
                );
                this.edit(updated);
            } else {
                const created = await this.pineai.createMeasurementProfile({
                    name: value.name.trim(),
                    description: value.description.trim(),
                    is_default: !!value.is_default,
                    context
                });
                this.edit(created);
            }
        }, this.selected ? 'Profile updated.' : 'Profile created.');
    }

    async archive(profile: MeasurementProfile): Promise<void> {
        if (!window.confirm(`Archive measurement profile "${profile.name}"?`)) {
            return;
        }
        await this.run(async () => {
            await this.pineai.archiveMeasurementProfile(profile);
            if (this.selected &&
                this.pineai.measurementProfileId(this.selected) ===
                this.pineai.measurementProfileId(profile)) {
                this.newProfile();
            }
        }, 'Profile archived.');
    }

    channels(): number[] {
        const values: number[] = [];
        (this.channelsText || '')
            .split(/[\s,]+/)
            .map((value) => parseInt(value, 10))
            .filter((value) => !isNaN(value) && value >= 1 && value <= 196)
            .forEach((value) => {
                if (values.indexOf(value) === -1) {
                    values.push(value);
                }
            });
        return values.sort((left, right) => left - right);
    }

    private async run(
        operation: () => Promise<void>,
        message: string
    ): Promise<void> {
        this.busy = true;
        this.errorMessage = '';
        this.successMessage = '';
        try {
            await operation();
            this.successMessage = message;
        } catch (error) {
            const failure = this.pineai.error(error);
            this.errorMessage = failure.code === 'revision_conflict' ||
                failure.code === 'profile_revision_conflict'
                ? `${failure.code}: The latest profile list was loaded. Review before retrying.`
                : `${failure.code}: ${failure.message}`;
            if (failure.code === 'revision_conflict' ||
                failure.code === 'profile_revision_conflict') {
                await this.pineai.refreshMeasurementProfiles(
                    this.includeArchived
                ).catch(() => undefined);
            }
        } finally {
            this.busy = false;
        }
    }
}
