'use client';

import { usePathname } from 'next/navigation';
import { Layout } from './Layout';

interface AuthAwareLayoutProps {
  children: React.ReactNode;
}

export function AuthAwareLayout({ children }: AuthAwareLayoutProps) {
  const pathname = usePathname();

  // Routes that don't need the dashboard layout
  const authRoutes = ['/login', '/register', '/forgot-password'];
  const isAuthRoute = authRoutes.includes(pathname);

  if (isAuthRoute) {
    // Return children directly for auth pages (they have their own layout)
    return <>{children}</>;
  }

  // Use dashboard layout for all other pages
  return <Layout>{children}</Layout>;
}