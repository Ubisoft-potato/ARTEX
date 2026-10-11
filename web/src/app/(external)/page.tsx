"use client";

import { useEffect } from "react";

export default function Home() {
  // 用硬跳转而非 next/navigation 的 redirect()：静态导出下 redirect() 走客户端软
  // 导航，会在这次路由切换里把 <html> 重新对账成 /function/tasks 这份静态产物自带
  // 的构建期默认属性（data-theme-mode="light" 等），把 ThemeBootScript 刚打上的
  // 深色模式覆盖掉——suppressHydrationWarning 只护住首次 hydrate，护不住这次切换。
  // 硬跳转会整页重载，ThemeBootScript 在新文档里重新从 cookie 读一遍，不会被覆盖。
  useEffect(() => {
    window.location.replace("/function/tasks");
  }, []);

  return null;
}
