import {
    RepeatableAuditWorkflowFacade
} from './repeatable-audit-workflow.facade';

describe('RepeatableAuditWorkflowFacade', () => {
    let facade: RepeatableAuditWorkflowFacade;

    beforeEach(() => {
        facade = new RepeatableAuditWorkflowFacade();
    });

    it('holds at most five raw scans in session memory', () => {
        for (let id = 1; id <= 6; id++) {
            facade.rememberRawScan({scan_id: id}, {APResults: [id]});
            facade.selectScan(`arm_${id}`, String(id));
        }

        expect(facade.rawScanCount()).toBe(5);
        expect(facade.selectedScan('arm_1')).toBeNull();
        expect(facade.selectedScan('arm_6').data.APResults).toEqual([6]);
    });

    it('clears all session-only evidence when the assessment changes', () => {
        facade.resetForAssessment('assessment_1');
        facade.selectPoint('mp_1', true);
        facade.rememberRawScan({scan_id: 17}, {APResults: []});
        facade.selectScan('arm_1', '17');

        facade.resetForAssessment('assessment_2');

        expect(facade.selectedPointIds).toEqual([]);
        expect(facade.rawScanCount()).toBe(0);
        expect(facade.selectedScan('arm_1')).toBeNull();
    });

    it('caps a run at sixteen point assignments', () => {
        for (let index = 0; index < 20; index++) {
            facade.selectPoint(`mp_${index}`, true);
        }

        expect(facade.selectedPointIds.length).toBe(16);
    });

    it('requires every immutable provenance pin', () => {
        facade.selectPoint('mp_1', true);
        facade.setAssignment({
            measurement_point_id: 'mp_1',
            measurement_profile_id: 'mprofile_1',
            measurement_profile_version_id: 'mprofile_r0001',
            baseline_version_id: 'baseline_v0001'
        });

        expect(facade.validAssignments()).toEqual([{
            measurement_point_id: 'mp_1',
            measurement_profile_id: 'mprofile_1',
            measurement_profile_version_id: 'mprofile_r0001',
            baseline_version_id: 'baseline_v0001'
        }]);
    });

    it('removes deselected assignments and ignores incomplete pins', () => {
        facade.selectPoint('mp_1', true);
        facade.setAssignment({
            measurement_point_id: 'mp_1',
            measurement_profile_id: 'mprofile_1',
            measurement_profile_version_id: '',
            baseline_version_id: 'baseline_v0001'
        });
        expect(facade.validAssignments()).toEqual([]);

        facade.selectPoint('mp_1', false);
        expect(facade.assignment('mp_1')).toBeNull();
    });

    it('keeps the same assessment state and updates feedback immutably', () => {
        facade.resetForAssessment('assessment_1');
        facade.selectPoint('mp_1', true);
        facade.resetForAssessment('assessment_1');
        expect(facade.pointSelected('mp_1')).toBeTrue();

        facade.setMessage('run', 'Ready');
        expect(facade.messages.run).toBe('Ready');
        facade.setError('run', {code: 'revision_conflict', message: 'Refresh'});
        expect(facade.messages.run).toBeUndefined();
        expect(facade.errors.run).toContain('revision_conflict');
        facade.clearFeedback('run');
        expect(facade.errors.run).toBeUndefined();
    });

    it('refreshes an existing raw scan without growing the cache', () => {
        facade.rememberRawScan({scan_id: 7}, {revision: 1});
        facade.rememberRawScan({scan_id: 7}, {revision: 2});
        facade.selectScan('arm_7', '7');

        expect(facade.rawScanCount()).toBe(1);
        expect(facade.selectedScan('arm_7').data.revision).toBe(2);
    });
});
