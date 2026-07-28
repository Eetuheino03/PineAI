import {WorkflowFacade} from './workflow.facade';
import {MeasurementProfile, ReconScan} from '../models';

describe('WorkflowFacade', () => {
    let facade: WorkflowFacade;

    beforeEach(() => {
        facade = new WorkflowFacade();
        facade.setAssessment({
            assessment_id: 'assessment_1',
            name: 'Office',
            revision: 1
        });
    });

    it('defaults to the seven-step baseline path without mutating state', () => {
        expect(facade.snapshot.mode).toBe('baseline');
        expect(facade.snapshot.current_step).toBe('measurement_profile');
        expect(facade.snapshot.selected_scans).toEqual([]);
        expect(facade.canProceed('measurement_profile')).toBeFalse();
    });

    it('requires two loaded scans for consensus and one for comparison', () => {
        const profile: MeasurementProfile = {
            measurement_profile_id: 'profile_1',
            revision: 2,
            name: 'Office preset',
            context: {
                location_id: 'office',
                measurement_point_id: 'desk',
                declared_channels: [1, 6, 11]
            }
        };
        facade.selectMeasurementProfile(profile);
        facade.rememberRawScan({scan_id: 1}, {APResults: []});
        expect(facade.canProceed('recon_scans')).toBeFalse();
        facade.rememberRawScan({scan_id: 2}, {APResults: []});
        expect(facade.canProceed('recon_scans')).toBeTrue();

        facade.setBaselineVersion('baseline_1');
        facade.clearSelectedScans();
        facade.rememberRawScan({scan_id: 3}, {APResults: []});
        expect(facade.snapshot.mode).toBe('comparison');
        expect(facade.canProceed('recon_scans')).toBeTrue();
    });

    it('keeps at most five raw scans and clears them on assessment change', () => {
        for (let index = 1; index <= 6; index += 1) {
            const scan: ReconScan = {scan_id: index};
            facade.rememberRawScan(scan, {id: index});
        }
        expect(facade.snapshot.selected_scans.length).toBe(5);
        expect(facade.rawScan('1')).toBeUndefined();
        expect(facade.rawScan('6')).toEqual({id: 6});

        facade.setAssessment({
            assessment_id: 'assessment_2',
            name: 'Plant',
            revision: 1
        });
        expect(facade.snapshot.selected_scans).toEqual([]);
        expect(facade.rawScan('6')).toBeUndefined();
    });

    it('does not mark analysis complete from a read-only comparison preview', () => {
        facade.setBaselineVersion('baseline_1');
        facade.setComparison('comparison_preview', true, false);
        expect(facade.canProceed('baseline_comparison')).toBeTrue();
        expect(facade.canProceed('analysis_evidence')).toBeFalse();

        facade.confirmAssuranceProfile();
        facade.setComparison('comparison_1', true, true);
        expect(facade.canProceed('analysis_evidence')).toBeTrue();
    });
});
