/**
 * Next.js API Route - Secure proxy to Cloudflare Worker
 * This route handles the upload authentication securely on the server-side
 */

import { NextRequest, NextResponse } from 'next/server';

export async function POST(request: NextRequest) {
  try {
    const authSecret = process.env.UPLOAD_AUTH_SECRET;
    if (!authSecret) {
      console.error('UPLOAD_AUTH_SECRET not configured');
      return NextResponse.json({ 
        success: false, 
        error: 'Server configuration error' 
      }, { status: 500 });
    }

    const workerUrl = process.env.NEXT_PUBLIC_API_URL;
    if (!workerUrl) {
      console.error('NEXT_PUBLIC_API_URL not configured');
      return NextResponse.json({ 
        success: false, 
        error: 'Server configuration error' 
      }, { status: 500 });
    }

    console.log(`Proxying upload request to Worker: ${workerUrl}/api/upload`);

    const formData = await request.formData();
    
    const workerResponse = await fetch(`${workerUrl}/api/upload`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${authSecret}`,
      },
      body: formData,
    });

    console.log(`Worker response status: ${workerResponse.status}`);

    if (!workerResponse.ok) {
      const errorText = await workerResponse.text();
      console.error('Worker error response:', errorText);
      return NextResponse.json({ 
        success: false, 
        error: `Upload failed: ${workerResponse.status}` 
      }, { status: workerResponse.status });
    }

    const result = await workerResponse.json();
    console.log('Upload proxy successful');
    return NextResponse.json(result);

  } catch (error) {
    console.error('Upload proxy error:', error);
    return NextResponse.json({ 
      success: false, 
      error: 'Upload failed' 
    }, { status: 500 });
  }
}
