import { useState, useCallback } from 'react';

export interface Toast {
  id: string;
  title: string;
  description?: string;
  variant?: 'default' | 'destructive' | 'success' | 'warning' | 'info';
  duration?: number;
}

interface ToastContextType {
  toasts: Toast[];
  toast: (toast: Omit<Toast, 'id'>) => void;
  dismiss: (id?: string) => void;
}

// Simple toast implementation
let toastId = 0;
const activeToasts: Toast[] = [];

export function useToast(): { toast: (toast: Omit<Toast, 'id'>) => { dismiss: () => void } } {
  const [, forceUpdate] = useState({});

  const toast = useCallback((toastData: Omit<Toast, 'id'>) => {
    const id = `toast-${++toastId}`;
    
    const newToast: Toast = {
      id,
      variant: 'default',
      ...toastData,
      duration: toastData.duration || 3000,
    };

    activeToasts.push(newToast);
    
    // Auto-dismiss after duration
    if (newToast.duration && newToast.duration > 0 && newToast.duration < 1000000) {
      setTimeout(() => {
        const index = activeToasts.findIndex(t => t.id === id);
        if (index > -1) {
          activeToasts.splice(index, 1);
          forceUpdate({});
        }
      }, newToast.duration);
    }

    // Enhanced console logging with variant colors
    const variantPrefix = newToast.variant?.toUpperCase() || 'DEFAULT';
    console.log(`[${variantPrefix}] ${newToast.title}${newToast.description ? ': ' + newToast.description : ''}`);
    
    forceUpdate({});

    return {
      dismiss: () => {
        const index = activeToasts.findIndex(t => t.id === id);
        if (index > -1) {
          activeToasts.splice(index, 1);
          forceUpdate({});
        }
      }
    };
  }, []);

  return { toast };
}