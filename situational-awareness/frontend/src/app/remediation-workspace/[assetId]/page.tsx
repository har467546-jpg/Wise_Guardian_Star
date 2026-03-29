import RemediationWorkspaceView from "@/components/RemediationWorkspaceView";

export default async function InteractiveRemediationAssetPage({ params }: { params: Promise<{ assetId: string }> }) {
  const { assetId } = await params;
  return <RemediationWorkspaceView assetId={assetId} />;
}
