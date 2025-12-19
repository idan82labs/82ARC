import { SignUp } from '@clerk/nextjs';

export default function SignUpPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-extrabold text-slate-900 mb-2">Aegis.</h1>
          <p className="text-slate-500">Create your account</p>
        </div>
        <SignUp afterSignUpUrl="/dashboard" signInUrl="/sign-in" />
      </div>
    </div>
  );
}
