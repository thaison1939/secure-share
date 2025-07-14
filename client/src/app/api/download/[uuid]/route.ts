import { NextRequest, NextResponse } from 'next/server';

// client/src/app/api/download/[uuid]/route.ts

export async function GET(
  request: NextRequest,
  { params }: { params: { uuid: string } }
) {
  console.log('🔍 Download API route called for UUID:', params.uuid);
  
  const { uuid } = params;
  
  if (!uuid) {
    return NextResponse.json({ error: 'UUID is required' }, { status: 400 });
  }
  
  const workerUrl = process.env.NEXT_PUBLIC_API_URL;
  if (!workerUrl) {
    return NextResponse.json({ error: 'Server configuration error' }, { status: 500 });
  }
  
  try {
    console.log('🚀 Forwarding download request to worker:', `${workerUrl}/api/download/${uuid}`);
    
    const workerResponse = await fetch(`${workerUrl}/api/download/${uuid}`, {
      method: 'GET',
      headers: {
        'User-Agent': 'NextJS-Download-Proxy/1.0'
      }
    });
    
    console.log('📡 Worker download response:', workerResponse.status);
    
    if (!workerResponse.ok) {
      const errorText = await workerResponse.text();
      console.error('❌ Worker download error:', errorText);
      return NextResponse.json({ error: 'File not found' }, { status: 404 });
    }
    
    const fileData = await workerResponse.arrayBuffer();
    const contentType = workerResponse.headers.get('content-type') || 'application/octet-stream';
    const contentDisposition = workerResponse.headers.get('content-disposition') || 'attachment';
    
    return new NextResponse(fileData, {
      headers: {
        'Content-Type': contentType,
        'Content-Disposition': contentDisposition,
        'X-Original-Filename': workerResponse.headers.get('X-Original-Filename') || '',
        'X-Remaining-Downloads': workerResponse.headers.get('X-Remaining-Downloads') || '',
        'X-Password-Hash-Base64': workerResponse.headers.get('X-Password-Hash-Base64') || '',
        'X-Nonce-Base64': workerResponse.headers.get('X-Nonce-Base64') || '',
        'X-Pwhash-Salt-Base64': workerResponse.headers.get('X-Pwhash-Salt-Base64') || '',
      },
    });
    
  } catch (error) {
    console.error('💥 Download error:', error);
    return NextResponse.json({ error: 'Download failed' }, { status: 500 });
  }
}