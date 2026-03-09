import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { RouterModule } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { SBOMListItem } from '../../core/api.models';

@Component({
  selector: 'app-sbom-list',
  standalone: true,
  imports: [CommonModule, ScrollingModule, RouterModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="sbom-list">
      <h1>SBOM Explorer</h1>

      <cdk-virtual-scroll-viewport itemSize="56" class="viewport">
        <div *cdkVirtualFor="let sbom of sboms; trackBy: trackBySbom" class="sbom-row">
          <a [routerLink]="['/sboms', sbom.sbom_id]" class="sbom-link">
            <span class="name">{{ sbom.document_name || sbom.source_file }}</span>
            <span class="version badge">{{ sbom.spdx_version }}</span>
            <span class="packages">{{ sbom.package_count }} packages</span>
            <span class="vulns" [class.has-vulns]="sbom.vuln_count > 0">
              {{ sbom.vuln_count }} vulns
            </span>
            <span class="date">{{ sbom.ingested_at | date:'short' }}</span>
          </a>
        </div>
      </cdk-virtual-scroll-viewport>
    </div>
  `,
  styles: [`
    .sbom-list { padding: 24px; height: 100%; display: flex; flex-direction: column; }
    h1 { margin: 0 0 16px; font-size: 1.1rem; font-weight: 700; letter-spacing: -0.02em; }
    .viewport { flex: 1; min-height: 400px; }
    .sbom-row { height: 52px; display: flex; align-items: center; border-bottom: 1px solid var(--border); }
    .sbom-link {
      display: flex; align-items: center; gap: 16px; width: 100%;
      padding: 0 12px; text-decoration: none; color: inherit;
    }
    .sbom-link:hover { background: var(--surface-alt); }
    .name { flex: 1; font-weight: 500; font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .badge { background: var(--bg); color: var(--text-secondary); padding: 2px 6px; border-radius: 2px; font-size: 0.7rem; font-weight: 500; }
    .packages { color: var(--text-secondary); font-size: 0.8rem; width: 110px; }
    .vulns { font-size: 0.8rem; width: 80px; color: var(--text-secondary); }
    .has-vulns { color: var(--severity-critical); font-weight: 600; }
    .date { color: var(--text-muted); font-size: 0.75rem; width: 110px; }
  `],
})
export class SbomListComponent implements OnInit {
  sboms: SBOMListItem[] = [];

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.api.getSboms(1, 1000).subscribe((response) => {
      this.sboms = response.data;
      this.cdr.markForCheck();
    });
  }

  trackBySbom(_index: number, item: SBOMListItem): string {
    return item.sbom_id;
  }
}

