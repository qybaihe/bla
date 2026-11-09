export interface WebsiteI18nLocaleCoverage {
  readonly keys: number;
  readonly missingFromEnglish: number;
}

export interface WebsiteI18nCoverage {
  readonly referenceLocale: string;
  readonly referenceKeys: number;
  readonly locales: Readonly<Record<string, WebsiteI18nLocaleCoverage>>;
}

export interface WebsiteVerifyResult {
  readonly ok: boolean;
  readonly pagesChecked: number;
  readonly linksChecked: number;
  readonly errors: readonly string[];
  readonly i18nCoverage: WebsiteI18nCoverage | null;
}

export function verifyWebsiteDirectory(websiteRoot?: string): WebsiteVerifyResult;