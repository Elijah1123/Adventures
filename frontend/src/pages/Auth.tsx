import React, { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import { toast } from "react-hot-toast";

const Auth: React.FC = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  
  const { login, signup, isAuthenticated, user, checkAuth } = useAuth();
  const navigate = useNavigate();

  // Debug: Log auth state changes
  useEffect(() => {
    console.log("🔍 Auth Component - Auth state:", {
      isAuthenticated,
      user: user ? user.username : null,
    });
  }, [isAuthenticated, user]);

  // Check if user is already logged in
  useEffect(() => {
    const checkUserAuth = async () => {
      console.log("🔍 Checking initial auth status...");
      await checkAuth();
      
      if (isAuthenticated) {
        console.log("✅ User already authenticated, redirecting...");
        navigate("/");
      }
    };
    
    checkUserAuth();
  }, [isAuthenticated, navigate, checkAuth]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      console.log("🔐 Auth form submitted:", {
        isLogin,
        username,
        email: isLogin ? "N/A (using username/email)" : email,
        passwordLength: password.length,
      });

      let success = false;

      if (isLogin) {
        // Login flow
        console.log("🔄 Attempting login...");
        success = await login(username, password);
        
        if (success) {
          console.log("✅ Login successful via AuthContext");
          toast.success("Login successful!");
          
          // Wait a moment for state to update
          setTimeout(() => {
            console.log("🔄 Redirecting after login...");
            console.log("📊 Current state after login:", {
              isAuthenticated,
              user: user?.username,
            });
            
            if (isAuthenticated) {
              console.log("✅ User authenticated, redirecting to home");
              navigate("/");
            } else {
              console.log("⚠️ Not authenticated after successful login, forcing auth check");
              // Force auth check and redirect
              checkAuth().then(() => {
                setTimeout(() => {
                  navigate("/");
                }, 500);
              });
            }
          }, 1000);
        } else {
          console.error("❌ Login failed via AuthContext");
          toast.error("Login failed. Please check your credentials.");
        }
      } else {
        // Signup flow
        if (password !== confirmPassword) {
          toast.error("Passwords do not match!");
          setLoading(false);
          return;
        }

        console.log("🔄 Attempting signup...");
        success = await signup(username, email, password);
        
        if (success) {
          console.log("✅ Signup successful via AuthContext");
          toast.success("Account created successfully!");
          
          // Auto-login after signup
          console.log("🔄 Auto-login after signup...");
          const loginSuccess = await login(username, password);
          
          if (loginSuccess) {
            setTimeout(() => {
              navigate("/");
            }, 1000);
          } else {
            // If auto-login fails, go to login page
            setIsLogin(true);
            setUsername(username);
            setPassword("");
            toast.success("Account created! Please login.");
          }
        } else {
          console.error("❌ Signup failed via AuthContext");
          toast.error("Signup failed. Please try again.");
        }
      }
    } catch (error) {
      console.error("❌ Auth error:", error);
      toast.error("An error occurred. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = async (demoUser: string) => {
    setLoading(true);
    
    // Demo credentials
    const credentials: Record<string, { username: string; password: string }> = {
      admin: { username: "admin", password: "admin123" },
      user: { username: "testuser", password: "test123" },
    };

    const creds = credentials[demoUser];
    if (!creds) return;

    console.log(`🔐 Attempting demo login as ${demoUser}...`);
    
    try {
      const success = await login(creds.username, creds.password);
      
      if (success) {
        toast.success(`Logged in as ${demoUser}!`);
        console.log("✅ Demo login successful");
        
        setTimeout(() => {
          navigate("/");
        }, 1000);
      } else {
        toast.error("Demo login failed. Please try manual login.");
      }
    } catch (error) {
      console.error("❌ Demo login error:", error);
      toast.error("Demo login failed.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-gray-100 p-4">
      <div className="w-full max-w-md">
        <div className="bg-white rounded-2xl shadow-xl p-8">
          {/* Logo/Header */}
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-gray-800 mb-2">
              MLima Adventures
            </h1>
            <p className="text-gray-600">
              {isLogin ? "Welcome back!" : "Create your account"}
            </p>
          </div>

          {/* Demo Login Buttons */}
          {isLogin && (
            <div className="mb-6">
              <p className="text-sm text-gray-600 mb-3 text-center">
                Try demo accounts:
              </p>
              <div className="grid grid-cols-2 gap-3">
                <button
                  onClick={() => handleDemoLogin("admin")}
                  disabled={loading}
                  className="flex-1 bg-purple-100 text-purple-700 py-2 px-4 rounded-lg font-medium hover:bg-purple-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Admin Demo
                </button>
                <button
                  onClick={() => handleDemoLogin("user")}
                  disabled={loading}
                  className="flex-1 bg-blue-100 text-blue-700 py-2 px-4 rounded-lg font-medium hover:bg-blue-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  User Demo
                </button>
              </div>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-6">
            {!isLogin && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Email
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition"
                  placeholder="Enter your email"
                  required
                  disabled={loading}
                />
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                {isLogin ? "Username or Email" : "Username"}
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition"
                placeholder={isLogin ? "Enter username or email" : "Choose a username"}
                required
                disabled={loading}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition"
                placeholder="Enter password"
                required
                minLength={6}
                disabled={loading}
              />
            </div>

            {!isLogin && (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Confirm Password
                </label>
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition"
                  placeholder="Confirm your password"
                  required
                  minLength={6}
                  disabled={loading}
                />
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-blue-600 to-blue-700 text-white py-3 px-4 rounded-lg font-semibold hover:from-blue-700 hover:to-blue-800 focus:ring-4 focus:ring-blue-300 transition-all disabled:opacity-70 disabled:cursor-not-allowed"
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin h-5 w-5 mr-3 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  {isLogin ? "Logging in..." : "Creating Account..."}
                </span>
              ) : (
                isLogin ? "Sign In" : "Create Account"
              )}
            </button>
          </form>

          {/* Toggle between login/signup */}
          <div className="mt-8 text-center">
            <p className="text-gray-600">
              {isLogin ? "Don't have an account?" : "Already have an account?"}{" "}
              <button
                onClick={() => {
                  setIsLogin(!isLogin);
                  // Clear password fields when toggling
                  setPassword("");
                  setConfirmPassword("");
                }}
                className="text-blue-600 font-medium hover:text-blue-800 transition-colors"
                disabled={loading}
              >
                {isLogin ? "Sign up" : "Sign in"}
              </button>
            </p>
          </div>

          {/* Debug info (remove in production) */}
          <div className="mt-6 pt-6 border-t border-gray-200">
            <p className="text-xs text-gray-500 text-center">
              Debug: Auth State - {isAuthenticated ? "Authenticated" : "Not Authenticated"}
              {user && ` | User: ${user.username}`}
            </p>
          </div>
        </div>

        {/* Home link */}
        <div className="text-center mt-6">
          <Link
            to="/"
            className="text-gray-600 hover:text-gray-800 transition-colors inline-flex items-center"
          >
            <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            Back to Home
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Auth;