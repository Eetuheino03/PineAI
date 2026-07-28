import { FormBuilder } from '@angular/forms';
import { ActivityComponent } from './activity.component';
import { AssessmentsComponent } from './assessments.component';
import { BaselinesComponent } from './baselines.component';

describe('Baseline & Drift UI contracts', () => {
    const service: any = {
        activeAssessment: null,
        assessments: [],
        errorText: () => 'request_failed: failed'
    };

    it('matches the backend assessment field limits', () => {
        const component = new AssessmentsComponent(
            service,
            new FormBuilder()
        );
        component.form.setValue({name: '', location: '', notes: ''});
        expect(component.form.invalid).toBeTrue();

        component.form.setValue({
            name: 'N'.repeat(100),
            location: 'L'.repeat(200),
            notes: 'T'.repeat(2000)
        });
        expect(component.form.valid).toBeTrue();

        component.form.get('notes').setValue('T'.repeat(2001));
        expect(component.form.invalid).toBeTrue();
    });

    it('accepts the full 128-character backend baseline label limit', () => {
        const component = new BaselinesComponent(service);
        component.label.setValue('B'.repeat(128));
        expect(component.label.valid).toBeTrue();
        component.label.setValue('B'.repeat(129));
        expect(component.label.invalid).toBeTrue();
    });

    it('renders the append-only audit timestamp field', () => {
        const component = new ActivityComponent(service);
        expect(component.eventTime({
            recorded_at: '2026-07-28T08:00:00Z'
        })).toBe('2026-07-28T08:00:00Z');
    });
});
