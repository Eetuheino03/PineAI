import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { PineAIComponent } from './components/PineAI.component';
import { OverviewComponent } from './components/overview.component';
import { ReconComponent } from './components/recon.component';
import { TargetsComponent } from './components/targets.component';
import { EngagementComponent } from './components/engagement.component';
import { AdvisorComponent } from './components/advisor.component';
import { AdaptiveReconComponent } from './components/adaptive-recon.component';
import { ActivityComponent } from './components/activity.component';
import { SettingsComponent } from './components/settings.component';
import { RouterModule, Routes } from '@angular/router';

import {MaterialModule} from './modules/material/material.module';
import {FlexLayoutModule} from '@angular/flex-layout';

import {FormsModule, ReactiveFormsModule} from '@angular/forms';

const routes: Routes = [
    { path: '', component: PineAIComponent }
];

@NgModule({
    declarations: [
        PineAIComponent,
        OverviewComponent,
        ReconComponent,
        TargetsComponent,
        EngagementComponent,
        AdvisorComponent,
        AdaptiveReconComponent,
        ActivityComponent,
        SettingsComponent
    ],
    imports: [
        CommonModule,
        RouterModule.forChild(routes),
        MaterialModule,
        FlexLayoutModule,
        FormsModule,
        ReactiveFormsModule,
    ],
    exports: [PineAIComponent]
})
export class PineAIModule { }
