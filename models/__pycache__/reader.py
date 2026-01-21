import pymupdf  # The library is imported as 'fitz'

@app.route('/read/<filename>')
def read_file(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file_ext = filename.rsplit('.', 1)[1].lower()
    extracted_text = ""

    try:
        if file_ext == 'pdf':
            # Extract text from PDF
            doc = pymupdf.open(filepath)
            for page in doc:
                extracted_text += page.get_text()
            doc.close()
        elif file_ext == 'epub':
            # Extract text from EPUB
            doc = pymupdf.open(filepath)  # PyMuPDF also opens EPUBs
            for page in doc:
                extracted_text += page.get_text()
            doc.close()
        else:
            flash('Unsupported file format.')
            return redirect(url_for('upload_file'))
    except Exception as e:
        flash(f'An error occurred while reading the file: {e}')
        return redirect(url_for('upload_file'))

    # Pass the extracted text to a template for display
    return render_template('reader.html', 
                           title=filename, 
                           content=extracted_text)