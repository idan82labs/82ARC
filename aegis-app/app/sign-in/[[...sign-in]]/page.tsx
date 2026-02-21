import { SignIn } from '@clerk/nextjs';

export default function SignInPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-extrabold text-slate-900 mb-2">Aegis.</h1>
          <p className="text-slate-500">Sign in to your account</p>
        </div>
        <SignIn afterSignInUrl="/dashboard" signUpUrl="/sign-up" />
      </div>
    </div>
  );
}
