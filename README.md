<h1>MultiFile Superencryption</h1>
<br />

<p>A program that allows merging multiple files into one and regenerating them given the correct password</p>

<h2>Requirements</h2>
<ul>
  <li>CMake 3.12 or higher</li>
  <li>OpenSSL 3.0 or higher</li>
</ul>

<h2>Compilation</h2>
<p>Clone the repository onto your local system and run the following commands (in bash):</p>
<pre>
  <code>cmake -S . -B build</code>
  <code>cmake --build build</code>
</pre>
The <code>mfsencrypt</code> executable will be generated in the <code>build/</code> directory

<h2>Encryption</h2>
<h3>Usage<sup>*</sup>:</h3>
<pre><code>./mfsencrypt FILES... -k KEYS... -o OUTPUT [-p PADDING] [-f FAKES]</code></pre>
<ol>
  <li><code>FILES...</code>: The paths to the files to merge</li>
  <li><code>KEYS...</code>: The keys corresponding to each file (the number of keys must equal the number of files)</li>
  <li><code>OUTPUT</code>: The name of the merged file</li>
  <li><code>PADDING</code> (Optional): The number of additional blocks of padding to insert in front of each file</li>
  <li><code>FAKES</code> (Optional): The number of fake sets of data to add for increased security</li>
</ol>

<h3>Example:</h3>
<pre><code>./mfsencrypt foo.png bar.txt -k pass1 pass2 -o merged.mfsn -p 250 -f 51</code></pre>

<h2>Decryption</h2>
<h3>Usage<sup>*</sup>:</h3>
<pre><code>./mfsencrypt -d FILE -k KEY -o OUTPUT</code></pre>
<ol>
  <li><code>FILE</code>: The path to the merged file</li>
  <li><code>KEY</code>: The key of the file to regenerate</li>
  <li><code>OUTPUT</code>: The name of the regenerated file</li>
</ol>

<h3>Example:</h3>
<pre><code>./mfsencrypt -d merged.mfsn -k pass2 -o bar.txt</code></pre>

<hr />
<p><sup>*</sup>The order of arguments must be exactly as specified</p>