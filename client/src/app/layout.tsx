import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import { Montserrat, Varela_Round } from 'next/font/google'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Secure Share - Encrypted File Sharing',
  description: 'Share files securely with end-to-end encryption',
}

const montserrat = Montserrat({ 
  subsets: ['latin'],
  weight: ['400', '600', '700'],
  variable: '--font-montserrat'
})

const varelaRound = Varela_Round({ 
  subsets: ['latin'],
  weight: ['400'],
  variable: '--font-varela'
})

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <head>
        {/* SEO-friendly font preloads */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700&family=Varela+Round:wght@400;700&display=swap"
          rel="stylesheet"
        />
        {/* FontAwesome with integrity check */}
        <link
          rel="stylesheet"
          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css"
          integrity="sha512-DTOQO9RWCH3ppGqcWaEA1BIZOC6xxalwEsw9c2QQeAIftl+Vegovlnee1c9QX4TctnWMn13TZye+giMm8e2LwA=="
          crossOrigin="anonymous"
          referrerPolicy="no-referrer"
        />
      </head>
      <body className={`${inter.className} bg-gray-600`} style={{fontFamily: 'Montserrat, sans-serif'}}>
        {children}
      </body>
    </html>
  )
}
