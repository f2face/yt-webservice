#!/usr/bin/env python
from __future__ import unicode_literals
from flask import Flask, jsonify, request
import sys

if __package__ is None and not hasattr(sys, 'frozen'):
    # direct call of __main__.py
    import os.path
    path = os.path.realpath(os.path.abspath(__file__))
    dir = '%s/lib' % os.path.dirname(os.path.dirname(path))
    sys.path.insert(0, dir)

app = Flask(__name__)
ydl_opts = {
    'youtube_include_dash_manifest': False
}


@app.route('/', methods=['GET'])
def retrieve_video_informations():
    import youtube_dl_basic as youtube_dl

    required_params = ['v']
    missing_params = [
        key for key in required_params
        if key not in request.args.keys()]

    if len(missing_params) == 0 and len(request.args['v']) == 11:
        try:
            yt_url = 'https://www.youtube.com/watch?v=%s' % request.args['v']
            with youtube_dl.YoutubeDL(ydl_opts) as ydl:
                result = ydl.extract_info(
                    yt_url,
                    download=False,
                    process=False
                )
                return jsonify(result)
        except Exception as e:
            resp = {
                "status": "failure",
                "error": "processing error",
                "message": str(e)
            }
            return jsonify(resp)
    else:
        resp = {
                "status": "failure",
                "error": "missing parameters",
                "message": "Provide %s in request" % (missing_params)
            }
        return jsonify(resp)


if __name__ == '__main__':
    # IP address where this web service will be running on.
    host = '0.0.0.0'

    # Port number where this web service will be running on.
    port = 8000

    app.run(host=host, port=port)
