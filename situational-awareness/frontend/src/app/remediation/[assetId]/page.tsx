import HostRemediationSessionView from "@/components/HostRemediationSessionView";

export default async function RemediationAssetPage({ params }: { params: Promise<{ assetId: string }> }) {
  const { assetId } = await params;
  return <HostRemediationSessionView assetId={assetId} />;
}
