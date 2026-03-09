import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { ApiService } from '../../core/api.service';
import { VEXStatementItem } from '../../core/api.models';

@Component({
  selector: 'app-vex-list',
  standalone: true,
  imports: [CommonModule, RouterModule, ScrollingModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="vex-list">
      <h1>VEX Statements</h1>
      <p class="subtitle">Vulnerability Exploitability eXchange – vendor assessments of vulnerability impact.</p>

      <cdk-virtual-scroll-viewport itemSize="96" class="viewport">
        <div *cdkVirtualFor="let stmt of statements; trackBy: trackByStmt" class="vex-row">
          <span class="status-badge" [class]="'status-' + stmt.status">
            {{ formatStatus(stmt.status) }}
          </span>
          <div class="vex-info">
            <div class="top-line">
              <span class="vuln-id">{{ stmt.vuln_id }}</span>
              <span class="purl">{{ stmt.product_purl }}</span>
            </div>
            <div class="mid-line">
              <span class="justification" *ngIf="stmt.justification">
                {{ formatJustification(stmt.justification) }}
              </span>
              <span class="impact" *ngIf="stmt.impact_statement">
                {{ stmt.impact_statement }}
              </span>
              <span class="action" *ngIf="stmt.action_statement">
                Action: {{ stmt.action_statement }}
              </span>
            </div>
            <div class="sbom-line" *ngIf="stmt.affected_sboms?.length">
              <span class="sbom-label">Affected SBOMs:</span>
              <a *ngFor="let sbom of stmt.affected_sboms"
                 [routerLink]="['/sboms', sbom.sbom_id]"
                 class="sbom-link"
                 [title]="sbom.sbom_id">
                {{ sbom.document_name }}
              </a>
            </div>
            <div class="sbom-line none" *ngIf="!stmt.affected_sboms?.length">
              <span class="no-sboms">No matching SBOMs found</span>
            </div>
          </div>
          <span class="date">{{ stmt.vex_timestamp | date:'short' }}</span>
        </div>
      </cdk-virtual-scroll-viewport>

      <div *ngIf="loaded && statements.length === 0" class="empty-state">
        <div class="empty-icon">📋</div>
        <h2>No VEX Statements Found</h2>
        <p>VEX (Vulnerability Exploitability eXchange) statements provide vendor assessments of how vulnerabilities affect specific products.</p>
        <div class="how-to">
          <h3>How to add VEX data:</h3>
          <ol>
            <li>Create <code>.openvex.json</code> or <code>.vex.json</code> files following the <a href="https://openvex.dev" target="_blank">OpenVEX spec</a></li>
            <li>Place them alongside your SBOMs in the data directory</li>
            <li>Re-trigger ingestion: <code>make re-ingest</code></li>
          </ol>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .vex-list { padding: 24px; height: 100%; display: flex; flex-direction: column; }
    h1 { margin: 0; font-size: 1.1rem; font-weight: 700; letter-spacing: -0.02em; }
    .subtitle { color: var(--text-secondary); font-size: 0.8rem; margin: 4px 0 16px; }
    .viewport { flex: 1; min-height: 400px; }
    .vex-row {
      height: 96px; display: flex; align-items: center; gap: 14px;
      padding: 8px 12px; border-bottom: 1px solid var(--border);
    }
    .status-badge {
      padding: 3px 8px; border-radius: 2px; font-size: 0.65rem; font-weight: 600;
      text-transform: uppercase; min-width: 110px; text-align: center;
      letter-spacing: 0.03em; flex-shrink: 0;
    }
    .status-not_affected { background: var(--status-success-bg); color: var(--status-success); }
    .status-affected { background: var(--severity-critical-bg); color: var(--severity-critical); }
    .status-fixed { background: var(--status-info-bg); color: var(--accent-hover); }
    .status-under_investigation { background: var(--severity-high-bg); color: var(--status-warning); }
    .vex-info { flex: 1; display: flex; flex-direction: column; gap: 3px; overflow: hidden; }
    .top-line { display: flex; gap: 12px; align-items: center; }
    .vuln-id { font-weight: 600; font-size: 0.85rem; }
    .purl { color: var(--accent); font-size: 0.75rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .mid-line { display: flex; gap: 8px; font-size: 0.73rem; color: var(--text-secondary); overflow: hidden; }
    .justification { background: var(--bg); padding: 1px 5px; border-radius: 2px; white-space: nowrap; }
    .impact, .action { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sbom-line { display: flex; align-items: center; gap: 5px; flex-wrap: wrap; }
    .sbom-line.none { opacity: 0.4; }
    .sbom-label { font-size: 0.68rem; color: var(--text-muted); }
    .sbom-link {
      font-size: 0.68rem; color: var(--accent); text-decoration: none;
      background: var(--bg); padding: 1px 6px; border-radius: 2px; white-space: nowrap;
    }
    .sbom-link:hover { background: var(--border); text-decoration: underline; }
    .no-sboms { font-size: 0.68rem; color: var(--text-muted); }
    .date { color: var(--text-muted); font-size: 0.75rem; min-width: 80px; flex-shrink: 0; }
    .empty-state {
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      padding: 48px 24px; text-align: center; color: var(--text-secondary);
    }
    .empty-icon { font-size: 2.5rem; margin-bottom: 12px; }
    .empty-state h2 { margin: 0 0 8px; font-size: 1rem; font-weight: 600; color: var(--text); }
    .empty-state p { max-width: 500px; font-size: 0.85rem; line-height: 1.5; margin: 0 0 20px; }
    .how-to {
      text-align: left; background: var(--surface-alt); border: 1px solid var(--border);
      border-radius: 2px; padding: 16px 20px; max-width: 460px;
    }
    .how-to h3 { margin: 0 0 8px; font-size: 0.85rem; font-weight: 600; color: var(--text); }
    .how-to ol { margin: 0; padding-left: 20px; font-size: 0.8rem; line-height: 1.8; }
    .how-to code { background: var(--border); padding: 1px 4px; border-radius: 2px; font-size: 0.75rem; }
    .how-to a { color: var(--accent); text-decoration: none; }
  `],
})
export class VEXListComponent implements OnInit {
  statements: VEXStatementItem[] = [];
  loaded = false;

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.api.getVEXStatements(1, 5000).subscribe((response) => {
      this.statements = response.data;
      this.loaded = true;
      this.cdr.markForCheck();
    });
  }

  formatStatus(status: string): string {
    return status.replace(/_/g, ' ');
  }

  formatJustification(justification: string): string {
    return justification.replace(/_/g, ' ');
  }

  trackByStmt(_index: number, item: VEXStatementItem): string {
    return item.vex_id;
  }
}

