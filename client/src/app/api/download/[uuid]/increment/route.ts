import { NextRequest, NextResponse } from 'next/server';

export async function POST(
  request: NextRequest,
  { params }: { params: { uuid: string } }
) {
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

    const { uuid } = params;

    const workerResponse = await fetch(`${workerUrl}/api/download/${uuid}/increment`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${authSecret}`,
        'Content-Type': 'application/json',
      },
    });


    if (!workerResponse.ok) {
      const errorText = await workerResponse.text();
      console.error('Worker increment error:', errorText);
      return NextResponse.json({ 
        success: false, 
        error: `Increment failed: ${workerResponse.status}` 
      }, { status: workerResponse.status });
    }

    const result = await workerResponse.json();
    return NextResponse.json(result);

  } catch (error) {
    console.error('Increment proxy error:', error);
    return NextResponse.json({ 
      success: false, 
      error: 'Increment failed' 
    }, { status: 500 });
  }
}