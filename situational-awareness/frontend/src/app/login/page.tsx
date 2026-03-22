import LoginPage from "./LoginPage";
import "./login.css";

// 这里设置浏览器标签页显示的标题
export const metadata = {
  title: "登录 | 资产态势感知平台",
  description: "资产态势感知平台桌面控制台",
};

export default function Page() {
  return <LoginPage />;
}
