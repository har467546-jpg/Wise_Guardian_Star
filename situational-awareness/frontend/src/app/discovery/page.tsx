import DiscoveryForm from "@/components/DiscoveryForm";

export const metadata = {
  title: "资产发现 - 资产态势感知平台",
  description: "扫描并发现内网中的活跃资产与服务",
};

export default function DiscoveryPage() {
  return (
    <main style={{ padding: '24px', minHeight: '100vh', background: '#f5f5f5' }}>
      <DiscoveryForm />
    </main>
  );
}