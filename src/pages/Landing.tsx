import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';

export default function Landing() {
  return (
    <div className="mx-auto max-w-6xl px-6 pb-24 pt-16">
      <section className="relative">
        <div className="pointer-events-none absolute inset-x-0 -top-12 -z-10 mx-auto h-64 max-w-3xl bg-hero-grad blur-2xl" />
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="mx-auto max-w-3xl text-center"
        >
          <span className="chip">Post-quantum · Shamir · Client-side only</span>
          <h1 className="mt-5 text-balance text-4xl font-bold tracking-tight text-ink-50 md:text-6xl">
            Turn a secret into QR codes{' '}
            <span className="bg-gradient-to-br from-accent-200 via-accent-400 to-accent-500 bg-clip-text text-transparent">
              only quantum computers
            </span>{' '}
            can't read.
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-pretty text-lg leading-relaxed text-ink-300">
            SuperSecretSecrets encrypts your text with ML-KEM (FIPS&nbsp;203) and
            splits the key across multiple QR codes using Shamir's Secret Sharing.
            Give the codes to trustees; any&nbsp;T of&nbsp;N can help you recover
            the secret. Nothing ever leaves your browser.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="mx-auto mt-10 grid max-w-4xl gap-4 sm:grid-cols-2"
        >
          <ActionCard
            to="/encode"
            title="Encode a secret"
            body="Type or paste text, pick T-of-N, download or print the QR codes."
            cta="Encode →"
            primary
          />
          <ActionCard
            to="/recover"
            title="Recover a secret"
            body="Scan or upload your QR codes. Any threshold-many shares will decrypt."
            cta="Recover →"
          />
        </motion.div>

        <div className="mx-auto mt-16 grid max-w-4xl gap-4 sm:grid-cols-3">
          <Feature title="Post-quantum" body="ML-KEM-768 by default (ML-KEM-512 / 1024 available). AES-256-GCM for the payload." />
          <Feature title="T-of-N backup" body="Default 3-of-5. Any 3 trustees can help you recover; 2 or fewer learn nothing." />
          <Feature title="Zero server" body="Everything runs in your browser. No accounts, no uploads, no analytics." />
        </div>
      </section>
    </div>
  );
}

function ActionCard({
  to,
  title,
  body,
  cta,
  primary,
}: {
  to: string;
  title: string;
  body: string;
  cta: string;
  primary?: boolean;
}) {
  return (
    <Link
      to={to}
      className={`card-hover group relative overflow-hidden p-6 ${
        primary ? 'ring-1 ring-accent-400/30' : ''
      }`}
    >
      <div className="flex items-start justify-between">
        <h3 className="text-lg font-semibold text-ink-50">{title}</h3>
        {primary && <span className="chip">Recommended</span>}
      </div>
      <p className="mt-2 text-sm text-ink-300">{body}</p>
      <span className="mt-5 inline-flex items-center gap-1.5 text-sm font-medium text-accent-300 group-hover:text-accent-200">
        {cta}
      </span>
    </Link>
  );
}

function Feature({ title, body }: { title: string; body: string }) {
  return (
    <div className="card p-5">
      <h4 className="text-sm font-semibold text-ink-100">{title}</h4>
      <p className="mt-1.5 text-sm text-ink-300">{body}</p>
    </div>
  );
}
