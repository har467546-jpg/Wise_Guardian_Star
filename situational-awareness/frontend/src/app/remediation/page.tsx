import { redirect } from "next/navigation";

import RemediationAssetGalleryView from "@/components/RemediationAssetGalleryView";
import { buildRemediationAssetPath } from "@/lib/remediation";

function pickQueryValue(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) {
    return value[0] || null;
  }
  return value || null;
}

export default async function RemediationPage({
  searchParams,
}: {
  searchParams: Promise<{
    assetId?: string | string[];
    findingId?: string | string[];
    taskId?: string | string[];
  }>;
}) {
  const params = await searchParams;
  const assetId = pickQueryValue(params.assetId);
  if (assetId) {
    redirect(
      buildRemediationAssetPath(assetId, {
        findingId: pickQueryValue(params.findingId),
        taskId: pickQueryValue(params.taskId),
      }),
    );
  }
  return <RemediationAssetGalleryView />;
}
