import { createContext, useContext, useState, useEffect, ReactNode } from "react";

export interface User {
  id: number;
  username: string;
  email: string;
  phone_number?: string;
  is_admin: boolean;
  created_at: string;
  updated_at: string;
}

export interface AdminStats {
  dashboard: {
    total_users: number;
    total_adventures: number;
    total_bookings: number;
    total_revenue: number;
    recent_users: number;
    recent_bookings: number;
    recent_revenue: number;
  };
  analytics: {
    booking_status: { status: string; count: number }[];
    payment_status: { status: string; count: number }[];
    monthly_revenue: { year: number; month: number; revenue: number }[];
  };
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  setUser: (user: User | null) => void;
  login: (identifier: string, password: string) => Promise<boolean>;
  signup: (username: string, email: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
  refreshUser: () => Promise<void>;
  fetchAdminStats: () => Promise<AdminStats | null>;
  fetchAdminUsers: () => Promise<User[]>;
  fetchAdminBookings: () => Promise<any[]>;
  fetchUserBookings: () => Promise<any[]>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Base URL for all API calls
const API_BASE_URL = "https://mlima-adventures.onrender.com";

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  // Initialize auth on mount
  useEffect(() => {
    const initializeAuth = async () => {
      console.log("🔍 Initializing authentication...");
      
      // Check if we have a token in localStorage from previous session
      const token = localStorage.getItem('token');
      const storedUser = localStorage.getItem('user');
      
      if (token && storedUser) {
        try {
          const parsedUser = JSON.parse(storedUser);
          setUser(parsedUser);
          setIsAuthenticated(true);
          console.log("✅ Restored user from localStorage:", parsedUser.username);
        } catch (error) {
          console.error("❌ Failed to parse stored user:", error);
          localStorage.removeItem('token');
          localStorage.removeItem('user');
        }
      }
      
      // Always check with server to verify session
      await checkAuth();
      setLoading(false);
    };
    
    initializeAuth();
  }, []);

  // ----------------------
  // LOGIN (Session-based with token support)
  // ----------------------
  const login = async (identifier: string, password: string): Promise<boolean> => {
    try {
      console.log("🔐 Attempting login with:", identifier);
      
      const res = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        credentials: "include",
        body: JSON.stringify({
          email: identifier.includes("@") ? identifier : undefined,
          username: !identifier.includes("@") ? identifier : undefined,
          password
        }),
      });

      console.log("📡 Login response status:", res.status, res.statusText);
      
      // Check if response is JSON
      const contentType = res.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        console.error("❌ Server returned non-JSON response during login");
        const text = await res.text();
        console.error("📝 Response text:", text.substring(0, 200));
        return false;
      }

      const data = await res.json();
      console.log("✅ Login response data:", data);

      if (res.ok && data.user) {
        // Store user data
        setUser(data.user);
        setIsAuthenticated(true);
        
        // Store token if provided (for API calls)
        if (data.token) {
          localStorage.setItem('token', data.token);
          console.log("🔑 Token stored in localStorage");
        }
        
        // Store user data for persistence
        localStorage.setItem('user', JSON.stringify(data.user));
        
        console.log("✅ Login successful for user:", data.user.username);
        return true;
      }

      console.error("❌ Login failed:", data.message || "Unknown error");
      return false;
    } catch (err) {
      console.error("❌ Login request failed:", err);
      return false;
    }
  };

  // ----------------------
  // SIGNUP (Session-based)
  // ----------------------
  const signup = async (username: string, email: string, password: string): Promise<boolean> => {
    try {
      console.log("📝 Attempting signup with:", { username, email });
      
      const res = await fetch(`${API_BASE_URL}/api/auth/register`, {
        method: "POST",
        headers: { 
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        credentials: "include",
        body: JSON.stringify({ 
          username, 
          email, 
          password
        }),
      });

      console.log("📡 Signup response status:", res.status, res.statusText);
      
      const contentType = res.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        console.error("❌ Server returned non-JSON response during signup");
        const text = await res.text();
        console.error("📝 Response text:", text.substring(0, 200));
        return false;
      }

      const data = await res.json();
      console.log("✅ Signup response data:", data);

      if (res.ok && data.user) {
        setUser(data.user);
        setIsAuthenticated(true);
        
        if (data.token) {
          localStorage.setItem('token', data.token);
        }
        localStorage.setItem('user', JSON.stringify(data.user));
        
        return true;
      }

      console.error("❌ Signup failed:", data.message || "Unknown error");
      return false;
    } catch (err) {
      console.error("❌ Signup request failed:", err);
      return false;
    }
  };

  // ----------------------
  // LOGOUT
  // ----------------------
  const logout = async (): Promise<void> => {
    try {
      console.log("🚪 Attempting logout...");
      
      const res = await fetch(`${API_BASE_URL}/api/auth/logout`, {
        method: "POST",
        credentials: "include",
      });

      console.log("📡 Logout response status:", res.status, res.statusText);

      // Clear local state regardless of server response
      setUser(null);
      setIsAuthenticated(false);
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      
      console.log("✅ Logout completed (local state cleared)");
    } catch (err) {
      console.error("❌ Logout request failed:", err);
      // Still clear local state on error
      setUser(null);
      setIsAuthenticated(false);
      localStorage.removeItem('token');
      localStorage.removeItem('user');
    }
  };

  // ----------------------
  // CHECK AUTH - Updated with better error handling
  // ----------------------
  const checkAuth = async (): Promise<void> => {
    try {
      console.log("🔍 Checking authentication status...");
      
      const token = localStorage.getItem('token');
      const headers: HeadersInit = {
        "Content-Type": "application/json",
        "Accept": "application/json"
      };
      
      // Add token to headers if available
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      const res = await fetch(`${API_BASE_URL}/api/auth/check-auth`, {
        method: "GET",
        credentials: "include",
        headers,
      });

      console.log("📡 Check auth response status:", res.status, res.statusText);

      if (res.status === 401 || res.status === 403) {
        // Clear invalid auth data
        console.log("❌ Server rejected authentication");
        setUser(null);
        setIsAuthenticated(false);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        return;
      }

      if (!res.ok) {
        console.log("⚠️ Auth check failed, but not an auth error. Status:", res.status);
        return;
      }

      // Check if response is JSON
      const contentType = res.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        console.error("❌ Server returned non-JSON response during auth check");
        return;
      }

      const data = await res.json();
      console.log("✅ Check auth response data:", data);

      if (data.authenticated && data.user) {
        setUser(data.user);
        setIsAuthenticated(true);
        // Update stored user data
        localStorage.setItem('user', JSON.stringify(data.user));
        console.log("✅ User is authenticated:", data.user.username);
      } else if (data.user) {
        // Some endpoints just return user data
        setUser(data.user);
        setIsAuthenticated(true);
        localStorage.setItem('user', JSON.stringify(data.user));
        console.log("✅ User authenticated via user data");
      } else {
        setUser(null);
        setIsAuthenticated(false);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        console.log("❌ User is not authenticated");
      }
    } catch (err) {
      console.error("❌ Check auth request failed:", err);
      // Don't clear auth on network errors - keep existing state
    }
  };

  // ----------------------
  // REFRESH USER
  // ----------------------
  const refreshUser = async (): Promise<void> => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/auth/me`, {
        method: "GET",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
      });

      if (res.ok) {
        const data = await res.json();
        if (data.user) {
          setUser(data.user);
          localStorage.setItem('user', JSON.stringify(data.user));
          console.log("✅ User data refreshed");
        }
      }
    } catch (err) {
      console.error("❌ Failed to refresh user data:", err);
    }
  };

  // ----------------------
  // FETCH USER BOOKINGS - FIXED ENDPOINT
  // ----------------------
  const fetchUserBookings = async (): Promise<any[]> => {
    if (!user) {
      console.log("❌ User not logged in, cannot fetch bookings");
      return [];
    }

    try {
      console.log("📋 Fetching user bookings for:", user.username);
      
      const token = localStorage.getItem('token');
      const headers: HeadersInit = {
        "Content-Type": "application/json",
        "Accept": "application/json"
      };
      
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      // Try multiple possible endpoints
      let endpoint = `${API_BASE_URL}/api/bookings/user/${user.id}`;
      console.log("🔄 Trying endpoint:", endpoint);
      
      let res = await fetch(endpoint, {
        method: "GET",
        credentials: "include",
        headers,
      });

      // If 404, try alternative endpoints
      if (res.status === 404) {
        console.log("🔄 Trying alternative endpoint 1...");
        endpoint = `${API_BASE_URL}/api/bookings/my-bookings`;
        res = await fetch(endpoint, {
          method: "GET",
          credentials: "include",
          headers,
        });
      }
      
      if (res.status === 404) {
        console.log("🔄 Trying alternative endpoint 2...");
        endpoint = `${API_BASE_URL}/api/auth/bookings`;
        res = await fetch(endpoint, {
          method: "GET",
          credentials: "include",
          headers,
        });
      }

      console.log("📡 Bookings response status:", res.status, res.statusText);

      if (!res.ok) {
        console.error("❌ Failed to fetch user bookings, status:", res.status);
        return [];
      }

      // Check if response is JSON
      const contentType = res.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        console.error("❌ Server returned non-JSON response for bookings");
        return [];
      }

      const data = await res.json();
      console.log("✅ Bookings response data:", data);
      
      // Handle different response formats
      if (Array.isArray(data)) {
        console.log(`✅ Found ${data.length} bookings`);
        return data;
      } else if (data.bookings && Array.isArray(data.bookings)) {
        console.log(`✅ Found ${data.bookings.length} bookings`);
        return data.bookings;
      } else if (data.data && Array.isArray(data.data)) {
        console.log(`✅ Found ${data.data.length} bookings`);
        return data.data;
      }
      
      console.log("⚠️ No bookings found or unexpected format");
      return [];
    } catch (err) {
      console.error("❌ Failed to fetch user bookings:", err);
      return [];
    }
  };

  // ----------------------
  // ADMIN FUNCTIONS (keep as is, but with improved headers)
  // ----------------------
  const fetchAdminStats = async (): Promise<AdminStats | null> => {
    if (!user?.is_admin) {
      console.log("❌ User is not admin, cannot fetch stats");
      return null;
    }

    try {
      const token = localStorage.getItem('token');
      const headers: HeadersInit = {
        "Content-Type": "application/json",
        "Accept": "application/json"
      };
      
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      const res = await fetch(`${API_BASE_URL}/api/auth/admin/stats`, {
        method: "GET",
        credentials: "include",
        headers,
      });

      if (res.ok) {
        const data = await res.json();
        return data as AdminStats;
      }
      
      console.error("❌ Failed to fetch admin stats, status:", res.status);
      return null;
    } catch (err) {
      console.error("❌ Failed to fetch admin stats:", err);
      return null;
    }
  };

  const fetchAdminUsers = async (): Promise<User[]> => {
    if (!user?.is_admin) {
      console.log("❌ User is not admin, cannot fetch users");
      return [];
    }

    try {
      const token = localStorage.getItem('token');
      const headers: HeadersInit = {
        "Content-Type": "application/json",
        "Accept": "application/json"
      };
      
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      const res = await fetch(`${API_BASE_URL}/api/auth/admin/users`, {
        method: "GET",
        credentials: "include",
        headers,
      });

      if (res.ok) {
        const data = await res.json();
        return data.users || [];
      }
      
      console.error("❌ Failed to fetch admin users, status:", res.status);
      return [];
    } catch (err) {
      console.error("❌ Failed to fetch admin users:", err);
      return [];
    }
  };

  const fetchAdminBookings = async (): Promise<any[]> => {
    if (!user?.is_admin) {
      console.log("❌ User is not admin, cannot fetch bookings");
      return [];
    }

    try {
      const token = localStorage.getItem('token');
      const headers: HeadersInit = {
        "Content-Type": "application/json",
        "Accept": "application/json"
      };
      
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      
      const res = await fetch(`${API_BASE_URL}/api/auth/admin/bookings`, {
        method: "GET",
        credentials: "include",
        headers,
      });

      if (res.ok) {
        const data = await res.json();
        return data.bookings || [];
      }
      
      console.error("❌ Failed to fetch admin bookings, status:", res.status);
      return [];
    } catch (err) {
      console.error("❌ Failed to fetch admin bookings:", err);
      return [];
    }
  };

  // Loading state
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
          <p className="mt-4 text-muted-foreground">Loading authentication...</p>
        </div>
      </div>
    );
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated,
        setUser,
        login,
        signup,
        logout,
        checkAuth,
        refreshUser,
        fetchAdminStats,
        fetchAdminUsers,
        fetchAdminBookings,
        fetchUserBookings,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within an AuthProvider");
  return context;
};