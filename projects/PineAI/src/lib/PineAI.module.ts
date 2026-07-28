import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Routes } from '@angular/router';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { FlexLayoutModule } from '@angular/flex-layout';

import { MaterialModule } from './modules/material/material.module';
import { PineAIComponent } from './components/PineAI.component';
import { OverviewComponent } from './components/overview.component';
import { ReconComponent } from './components/recon.component';
import { AssessmentsComponent } from './components/assessments.component';
import { BaselinesComponent } from './components/baselines.component';
import { AssetsChangesComponent } from './components/assets-changes.component';
import { FindingsComponent } from './components/findings.component';
import { ReportsComponent } from './components/reports.component';
import { ActivityComponent } from './components/activity.component';
import { SettingsComponent } from './components/settings.component';

const routes: Routes = [
    {path: '', component: PineAIComponent}
];

@NgModule({
    declarations: [
        PineAIComponent,
        OverviewComponent,
        ReconComponent,
        AssessmentsComponent,
        BaselinesComponent,
        AssetsChangesComponent,
        FindingsComponent,
        ReportsComponent,
        ActivityComponent,
        SettingsComponent
    ],
    imports: [
        CommonModule,
        RouterModule.forChild(routes),
        MaterialModule,
        FlexLayoutModule,
        FormsModule,
        ReactiveFormsModule
    ],
    exports: [PineAIComponent]
})
export class PineAIModule {}
