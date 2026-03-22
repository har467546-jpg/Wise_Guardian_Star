import AssetDetailView from "@/components/AssetDetailView";

export default async function AssetDetailPage({ params }: { params: Promise<{ assetId: string }> }) {
  const { assetId } = await params;
  return <AssetDetailView assetId={assetId} />;
}
