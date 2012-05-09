require 'find'
require 'rubygems'
require './lib/probecraft'

module Project
  EXCLUDED_PATTERNS = [/\/\.git\//, /\.swp$/, /\.bak$/]
  def exclude?(file)
    true if EXCLUDED_PATTERNS.find{|patt| patt =~ file}
  end

  def gemspec
    Gem::Specification.new do |s|
      s.name = 'probecraft'
      s.description = Probecraft::ABOUT
      s.rubyforge_project = 'hsh'
      s.version = Probecraft::VERSION
      s.author = Probecraft::AUTHORS.first
      s.homepage = Probecraft::WEBSITE
      s.summary = "Probecraft is a way to play with the network"
      s.email = "lucas<@nospam@>dicioccio.fr"
      s.platform = Gem::Platform::RUBY
      s.files = manifest_files
      s.require_path = 'lib'
      #s.bindir = 'bin'
      #s.executables = ['']
      s.has_rdoc = false
    end
  end

  def manifest(mode=nil)
    str = 'Manifest'
    if mode and block_given?
      File.open(str, mode) do |file|
        yield file
      end
    end
    str
  end

  def manifest_files
    File.read(manifest).lines.map{|fn| fn.chomp}
  end

  extend self
end

file 'INFO' do 
  puts "Gathering INFO"
  File.open('INFO', 'w') do |f|
    begin
      require 'git'
      g = Git.open('.')
      sha1 = g.revparse(g.current_branch)
      f.puts sha1
      puts "OK"
    rescue Exception => err
      f.puts "could not determine Git-sha1 at packaging time"
      puts "KO (not fatal):  #{err}"
    end
  end
end

file Project.manifest => 'INFO' do |t|
  puts "Building #{t.name}"
  Project.manifest('w') do |file|
    Find.find('.') do |path|
      if File.file?(path) and not Project.exclude?(path)
        file.puts path 
      end
    end
  end
end

task :gem => Project.manifest do
  puts Gem::Builder.new(Project.gemspec).build
  rm 'INFO'
end

