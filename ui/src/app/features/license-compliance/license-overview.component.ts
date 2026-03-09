import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { ApiService } from '../../core/api.service';
import { LicenseComplianceItem } from '../../core/api.models';

@Component({
  selector: 'app-license-overview',
  standalone: true,
  imports: [CommonModule, RouterModule, ScrollingModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="license-overview">
      <h1>License Compliance</h1>

      <div class="categories">
        <div class="category-card permissive">
          <h3>Permissive</h3>
          <span class="count">{{ getCategoryCount('permissive') }}</span>
        </div>
        <div class="category-card copyleft">
          <h3>Copyleft</h3>
          <span class="count">{{ getCategoryCount('copyleft') }}</span>
        </div>
        <div class="category-card unknown">
          <h3>Unknown</h3>
          <span class="count">{{ getCategoryCount('unknown') }}</span>
        </div>
      </div>

      <h2>All Licenses</h2>
      <cdk-virtual-scroll-viewport [itemSize]="getItemHeight()" class="viewport">
        <div *cdkVirtualFor="let item of licenses; trackBy: trackByLicense" class="license-row">
          <div class="license-main">
            <span class="category-badge" [class]="'cat-' + item.category">{{ item.category }}</span>
            <span class="license-id">{{ item.license_id }}</span>
            <span class="pkg-count">{{ item.package_count }} packages</span>
            <span class="non-compliant" *ngIf="item.non_compliant_packages?.length">
              ⚠️ {{ item.non_compliant_packages!.length }} non-compliant
            </span>
          </div>
          <div class="sbom-links" *ngIf="item.affected_sboms?.length">
            <span class="sbom-label">SBOMs:</span>
            <a *ngFor="let sbom of item.affected_sboms"
               [routerLink]="['/sboms', sbom.sbom_id]"
               class="sbom-link"
               [title]="sbom.sbom_id">
              {{ sbom.document_name }}
            </a>
          </div>
        </div>
      </cdk-virtual-scroll-viewport>
    </div>
  `,
  styles: [`
    .license-overview { padding: 24px; height: 100%; display: flex; flex-direction: column; }
    h1 { margin: 0 0 16px; font-size: 1.1rem; font-weight: 700; letter-spacing: -0.02em; }
    h2 { margin: 0 0 12px; font-size: 0.9rem; font-weight: 600; }
    .categories { display: flex; gap: 8px; margin-bottom: 20px; }
    .category-card {
      flex: 1; padding: 16px; border-radius: 4px; text-align: center;
      border: 1px solid var(--border);
    }
    .category-card h3 { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-secondary); margin: 0 0 4px; font-weight: 600; }
    .permissive { background: var(--surface-alt); }
    .copyleft { background: var(--severity-critical-bg); }
    .unknown { background: var(--surface-alt); }
    .count { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }
    .viewport { flex: 1; min-height: 400px; }
    .license-row {
      display: flex; flex-direction: column; justify-content: center;
      padding: 8px 12px; border-bottom: 1px solid var(--border); min-height: 48px;
    }
    .license-main { display: flex; align-items: center; gap: 14px; }
    .category-badge {
      padding: 2px 7px; border-radius: 2px; font-size: 0.68rem; font-weight: 600;
      min-width: 84px; text-align: center; text-transform: uppercase; letter-spacing: 0.03em;
    }
    .cat-permissive { background: var(--status-success-bg); color: var(--status-success); }
    .cat-copyleft { background: var(--severity-critical-bg); color: var(--severity-critical); }
    .cat-unknown { background: var(--bg); color: var(--text-secondary); }
    .license-id { font-weight: 500; min-width: 200px; font-size: 0.85rem; }
    .pkg-count { color: var(--text-secondary); font-size: 0.8rem; }
    .non-compliant { color: var(--severity-critical); font-size: 0.8rem; }
    .sbom-links {
      display: flex; align-items: center; gap: 6px;
      padding: 3px 0 0 98px; flex-wrap: wrap;
    }
    .sbom-label { font-size: 0.68rem; color: var(--text-muted); }
    .sbom-link {
      font-size: 0.68rem; color: var(--accent); text-decoration: none;
      background: var(--bg); padding: 1px 6px; border-radius: 2px;
    }
    .sbom-link:hover { background: var(--border); text-decoration: underline; }
  `],
})
export class LicenseOverviewComponent implements OnInit {
  licenses: LicenseComplianceItem[] = [];

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.api.getLicenseCompliance().subscribe((data) => {
      this.licenses = data;
      this.cdr.markForCheck();
    });
  }

  getCategoryCount(category: string): number {
    return this.licenses
      .filter((l) => l.category === category)
      .reduce((sum, l) => sum + l.package_count, 0);
  }

  trackByLicense(_index: number, item: LicenseComplianceItem): string {
    return item.license_id;
  }

  getItemHeight(): number {
    return 72; // Taller rows to accommodate SBOM links
  }
}

