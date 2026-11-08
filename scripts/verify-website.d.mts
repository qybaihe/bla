export interface WebsiteVerifyResult {
  readonly ok: boolean;
  readonly pagesChecked: number;
  readonly linksChecked: number;
  readonly errors: readonly string[];
}

export function verifyWebsiteDirectory(websiteRoot?: string): WebsiteVerifyResult;
