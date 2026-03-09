import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { ApiService } from './api.service';
import { DashboardStats, PaginatedResponse, SBOMListItem, VulnerabilityListItem } from './api.models';

describe('ApiService', () => {
  let service: ApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });
    service = TestBed.inject(ApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch dashboard stats', () => {
    const mockStats: DashboardStats = {
      total_sboms: 100,
      total_packages: 5000,
      total_vulnerabilities: 42,
      critical_vulns: 5,
      high_vulns: 10,
      medium_vulns: 15,
      low_vulns: 12,
      license_breakdown: { permissive: 80, copyleft: 15, unknown: 5 },
    };

    service.getDashboardStats().subscribe((stats) => {
      expect(stats.total_sboms).toBe(100);
      expect(stats.total_vulnerabilities).toBe(42);
    });

    const req = httpMock.expectOne('/api/v1/stats/dashboard');
    expect(req.request.method).toBe('GET');
    req.flush(mockStats);
  });

  it('should fetch SBOMs with pagination', () => {
    const mockResp: PaginatedResponse<SBOMListItem> = {
      data: [{ sbom_id: '123', source_file: 'test.spdx.json', spdx_version: 'SPDX-2.3', document_name: 'test', package_count: 10, vuln_count: 2, ingested_at: '2025-01-01' }],
      total: 1,
      page: 1,
      page_size: 50,
    };

    service.getSboms(1, 50).subscribe((resp) => {
      expect(resp.data.length).toBe(1);
      expect(resp.data[0].sbom_id).toBe('123');
    });

    const req = httpMock.expectOne((r) => r.url === '/api/v1/sboms');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    req.flush(mockResp);
  });

  it('should fetch vulnerabilities with pagination', () => {
    const mockResp: PaginatedResponse<VulnerabilityListItem> = {
      data: [],
      total: 0,
      page: 1,
      page_size: 50,
    };

    service.getVulnerabilities(1, 50).subscribe((resp) => {
      expect(resp.data.length).toBe(0);
    });

    const req = httpMock.expectOne((r) => r.url === '/api/v1/vulnerabilities');
    expect(req.request.method).toBe('GET');
    req.flush(mockResp);
  });

  it('should fetch SBOM dependencies', () => {
    service.getSbomDependencies('abc-123').subscribe((nodes) => {
      expect(nodes).toEqual([]);
    });

    const req = httpMock.expectOne('/api/v1/sboms/abc-123/dependencies');
    expect(req.request.method).toBe('GET');
    req.flush([]);
  });

  it('should fetch license compliance', () => {
    service.getLicenseCompliance().subscribe((items) => {
      expect(items).toEqual([]);
    });

    const req = httpMock.expectOne('/api/v1/licenses/compliance');
    expect(req.request.method).toBe('GET');
    req.flush([]);
  });
});

